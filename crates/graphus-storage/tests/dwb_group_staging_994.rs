//! Regression gate for `rmp` #994 — **group staging**: one doublewrite barrier amortised over many
//! concurrent evictors, without any evictor ever concluding before its own bytes are durable.
//!
//! # What #994 changed
//!
//! `rmp` #993 moved the staging barrier out of the DWB device mutex, but every evictor still issued
//! its own. At 16 readers that was a 2.85 ms staging barrier plus a 2.68 ms home barrier per evicted
//! page — the ceiling stopped being contention and became fsync bandwidth. #994 lets an evictor ride
//! on a barrier another evictor is already issuing, when that barrier provably covers its bytes.
//!
//! # The invariant, and why it is easy to get wrong
//!
//! A follower must **recheck** after waking, never assume. If the leader started its `fdatasync`
//! *before* the follower's `pwrite`s completed, the leader's barrier did **not** make them durable —
//! and a follower that returned anyway would write its page home believing it has a doublewrite copy
//! that does not exist. A crash there loses the copy and leaves the torn home page unrepairable:
//! silent data loss, on the very path that exists to prevent it.
//!
//! [`a_late_arrival_never_concludes_on_the_leaders_barrier`] makes that case **deterministic** rather
//! than hoping a race shows up: it gates the leader *inside* its barrier, lets late evictors pile up
//! behind it with tickets the leader cannot have covered, and asserts each one's own copy is durable
//! at the moment it is about to write home. It fails if the recheck is removed — demonstrated, not
//! asserted.
//!
//! The protocol itself is `loom`-model-checked in `graphus-groupsync`; this file gates it through the
//! real `DwbPageStager`, on the real doublewrite layout.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use graphus_bufpool::{PageStager, page};
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, PAGE_SIZE, Page, SyncHandle};
use graphus_storage::dwb::{Dwb, DwbPageStager};

fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    // A page BUILT from a fill byte, not amended: its header LSN is whatever the fill happens to
    // spell, so the intended value must REPLACE it rather than be maxed against it (`rmp` #1029).
    page::reset_page_lsn(&mut p, graphus_core::Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

/// A gate that holds the **first** barrier open until the test releases it, so the follower path is
/// reached deterministically instead of by luck.
#[derive(Default, Debug)]
struct Gate {
    /// A leader is parked inside the barrier.
    leader_inside: Mutex<bool>,
    leader_arrived: Condvar,
    /// The test has released the leader.
    released: Mutex<bool>,
    release: Condvar,
}

impl Gate {
    fn leader_enters(&self) {
        let mut inside = self.leader_inside.lock().unwrap();
        *inside = true;
        self.leader_arrived.notify_all();
        drop(inside);
        let mut rel = self.released.lock().unwrap();
        while !*rel {
            rel = self.release.wait(rel).unwrap();
        }
    }

    fn wait_for_leader(&self) {
        let mut inside = self.leader_inside.lock().unwrap();
        while !*inside {
            inside = self.leader_arrived.wait(inside).unwrap();
        }
    }

    fn release_leader(&self) {
        let mut rel = self.released.lock().unwrap();
        *rel = true;
        self.release.notify_all();
    }
}

/// The durability model: writes land in a volatile cache; a barrier promotes whatever is in it at
/// the moment the barrier *starts* — which is exactly what a real `fdatasync` guarantees.
#[derive(Default, Debug)]
struct Core {
    durable: Vec<Page>,
    cache: std::collections::HashMap<u64, Page>,
    barriers: usize,
}

#[derive(Clone)]
struct GatedDevice {
    core: Arc<Mutex<Core>>,
    gate: Arc<Gate>,
    /// Gate only the first barrier; later ones run straight through.
    gate_first_only: bool,
}

impl GatedDevice {
    fn new(pages: u64, gate: Arc<Gate>, gate_first_only: bool) -> Self {
        Self {
            core: Arc::new(Mutex::new(Core {
                durable: vec![[0u8; PAGE_SIZE]; pages as usize],
                ..Core::default()
            })),
            gate,
            gate_first_only,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a valid copy of `home_id` is in the **durable** image right now.
    fn durably_holds(&self, home_id: u64) -> bool {
        self.lock()
            .durable
            .iter()
            .any(|p| page::verify_checksum(p) && page::page_id(p) == home_id)
    }

    fn barriers(&self) -> usize {
        self.lock().barriers
    }
}

#[derive(Debug)]
struct GatedHandle {
    core: Arc<Mutex<Core>>,
    gate: Arc<Gate>,
    gate_first_only: bool,
}

impl SyncHandle for GatedHandle {
    fn sync_data(&self) -> Result<()> {
        assert_eq!(
            graphus_core::latch::dwb_lock_depth(),
            0,
            "rmp #993/#994: the staging barrier ran with the DWB device mutex held"
        );
        // SNAPSHOT AT ENTRY: a real barrier makes durable exactly what was already written when it
        // started. Taking the snapshot before parking on the gate is what makes this model faithful —
        // pages written while the leader is parked must NOT become durable through this barrier.
        let snapshot: Vec<(u64, Page)> = {
            let c = self
                .core
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            c.cache.iter().map(|(k, v)| (*k, *v)).collect()
        };
        let first = {
            let mut c = self
                .core
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            c.barriers += 1;
            c.barriers == 1
        };
        if first || !self.gate_first_only {
            self.gate.leader_enters();
        } else {
            // A REAL barrier is milliseconds; a zero-cost one leaves no window for followers to
            // arrive, so there would be nothing to amortise and asserting amortisation over it would
            // be measuring the model, not the protocol. This models the production cost (the measured
            // staging barrier is ~2.8 ms at 16 readers).
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let mut c = self
            .core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (idx, bytes) in snapshot {
            c.durable[idx as usize] = bytes;
            c.cache.remove(&idx);
        }
        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        self.sync_data()
    }
}

impl BlockDevice for GatedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        let c = self.lock();
        *buf = c
            .cache
            .get(&page.0)
            .copied()
            .unwrap_or_else(|| c.durable[page.0 as usize]);
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.lock().cache.insert(page.0, *buf);
        Ok(())
    }
    fn sync_data(&mut self) -> Result<()> {
        let mut c = self.lock();
        c.barriers += 1;
        let staged: Vec<(u64, Page)> = c.cache.iter().map(|(k, v)| (*k, *v)).collect();
        for (idx, bytes) in staged {
            c.durable[idx as usize] = bytes;
        }
        c.cache.clear();
        Ok(())
    }
    fn sync_all(&mut self) -> Result<()> {
        self.sync_data()
    }
    fn sync_handle(&self) -> Option<Arc<dyn SyncHandle>> {
        Some(Arc::new(GatedHandle {
            core: Arc::clone(&self.core),
            gate: Arc::clone(&self.gate),
            gate_first_only: self.gate_first_only,
        }))
    }
    fn page_count(&self) -> u64 {
        self.lock().durable.len() as u64
    }
    fn extend(&mut self, additional: u64) -> Result<()> {
        let mut c = self.lock();
        for _ in 0..additional {
            c.durable.push([0u8; PAGE_SIZE]);
        }
        Ok(())
    }
}

/// **Criterion 5.** A late-arriving evictor must never conclude on a barrier that started before its
/// writes. Made deterministic by parking the leader inside its barrier while the followers stage.
///
/// Verified non-vacuous: with the follower recheck removed from
/// `graphus_groupsync::StagingBarrier::wait_durable` (a follower returning `Ok` on wake), the
/// followers conclude with their copies still volatile and the in-callback assertion below fires.
#[test]
fn a_late_arrival_never_concludes_on_the_leaders_barrier() {
    const FOLLOWERS: u64 = 4;
    let gate = Arc::new(Gate::default());
    let dev = GatedDevice::new(graphus_storage::dwb_device_pages(), Arc::clone(&gate), true);
    let observer = dev.clone();
    let dwb = Arc::new(Mutex::new(Dwb::new(dev).expect("dwb")));
    let stager = Arc::new(DwbPageStager::new(dwb));
    let violations = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|s| {
        // The LEADER: stages page 1 and parks inside its barrier.
        {
            let stager = Arc::clone(&stager);
            let observer = observer.clone();
            let violations = Arc::clone(&violations);
            s.spawn(move || {
                let img = make_page(1, 111, 0xA1);
                stager
                    .stage_and_sync(PageId(1), &img[..], &mut || {
                        if !observer.durably_holds(1) {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    })
                    .expect("leader stage");
            });
        }

        // Wait until the leader is genuinely inside the barrier before the followers stage, so their
        // tickets are provably issued after the leader's snapshot.
        gate.wait_for_leader();

        let staged = Arc::new(AtomicUsize::new(0));
        for f in 0..FOLLOWERS {
            let stager = Arc::clone(&stager);
            let observer = observer.clone();
            let violations = Arc::clone(&violations);
            let staged = Arc::clone(&staged);
            let home = 10 + f;
            s.spawn(move || {
                let img = make_page(home, 200 + home, 0xB0 | (f as u8));
                staged.fetch_add(1, Ordering::Relaxed);
                stager
                    .stage_and_sync(PageId(home), &img[..], &mut || {
                        // THE GATE: this follower is about to write home. Its OWN copy must be
                        // durable — the leader's barrier, which started before this follower even
                        // wrote, cannot have made it so.
                        if !observer.durably_holds(home) {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    })
                    .expect("follower stage");
            });
        }

        // Give the followers time to write their slots and queue on the barrier, then let the leader
        // finish. (Correctness does not depend on this sleep — it only makes the interesting
        // interleaving the common one.)
        while staged.load(Ordering::Relaxed) < FOLLOWERS as usize {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        gate.release_leader();
    });

    assert_eq!(
        violations.load(Ordering::Relaxed),
        0,
        "an evictor wrote home without its own staged copy being durable — the follower recheck is \
         missing or broken"
    );
    // Every page must be durable at the end.
    assert!(
        observer.durably_holds(1),
        "the leader's page must be durable"
    );
    for f in 0..FOLLOWERS {
        assert!(
            observer.durably_holds(10 + f),
            "follower page {} must be durable",
            10 + f
        );
    }
}

/// **The amortisation itself.** With many evictors in flight, barriers must be *fewer* than
/// evictions — otherwise `rmp` #994 changed nothing and every other assertion here would still pass.
///
/// This is the non-vacuity control for the feature: the correctness tests above hold just as well
/// with one barrier per eviction, so without this one the suite could not tell the two apart.
#[test]
fn barriers_are_amortised_across_concurrent_evictors() {
    const THREADS: u64 = 8;
    const ROUNDS: u64 = 25;
    // `gate_first_only = false` would park every barrier; instead we pre-release the gate so the
    // FIRST barrier runs straight through, and every later one pays the modelled ~2 ms latency —
    // the window in which followers accumulate.
    let gate = Arc::new(Gate::default());
    gate.release_leader();
    let dev = GatedDevice::new(graphus_storage::dwb_device_pages(), Arc::clone(&gate), true);
    let observer = dev.clone();
    let dwb = Arc::new(Mutex::new(Dwb::new(dev).expect("dwb")));
    let stager = Arc::new(DwbPageStager::new(dwb));
    let violations = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|s| {
        for t in 0..THREADS {
            let stager = Arc::clone(&stager);
            let observer = observer.clone();
            let violations = Arc::clone(&violations);
            s.spawn(move || {
                for r in 0..ROUNDS {
                    let home = t * 100 + r + 1;
                    let img = make_page(home, 1000 + home, (home & 0xFF) as u8);
                    let observer = observer.clone();
                    let violations = Arc::clone(&violations);
                    stager
                        .stage_and_sync(PageId(home), &img[..], &mut move || {
                            if !observer.durably_holds(home) {
                                violations.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(())
                        })
                        .expect("stage");
                }
            });
        }
    });

    let evictions = THREADS * ROUNDS;
    let barriers = observer.barriers() as u64;
    assert_eq!(
        violations.load(Ordering::Relaxed),
        0,
        "every evictor must see its own copy durable before writing home"
    );
    let (issued, piggybacked) = stager.barrier_counters();
    assert!(
        barriers < evictions,
        "group staging must amortise: {barriers} barriers for {evictions} evictions (issued={issued}, \
         piggybacked={piggybacked}). One barrier per eviction means `rmp` #994 is not in effect."
    );
}
