//! `columnar_footprint` — empirical storage measurement: the row-store property footprint of the
//! IoT/social property columns versus their `graphus-columnar`-encoded footprint.
//!
//! It models the columns exactly as the deterministic generators emit them (documented schemas in
//! `graphus-iot-gen` / `graphus-social-gen`) and contrasts:
//!
//! - **Row store** (the authoritative format, sizes code-verified in the columnar audit): every
//!   property value is a 46-byte `PropRecord` (25-byte MVCC header + key + type_tag + value_inline);
//!   a `String`/`List` value additionally overflows to the `strings.store` heap as 83-byte blocks of
//!   48-byte payload each. So a scalar costs 46 B; a short string costs 46 B + 83 B (one block).
//! - **Columnar** (this crate): one self-describing encoded blob per column.
//!
//! This is the "measure on real generator distributions before committing" step the audit asked for,
//! and the source of the storage figures in the columnar report. Output is deterministic (a fixed
//! SplitMix64 seed, no clock/threads), so the numbers reproduce across runs and hosts.

use graphus_columnar::{dictionary, gorilla, integer};

const PROP_RECORD: usize = 46; // bytes per row-store PropRecord (25B MVCC header + fields)
const HEAP_BLOCK: usize = 83; // bytes per strings.store overflow block
const HEAP_PAYLOAD: usize = 48; // usable payload per overflow block

/// Bytes a single `String` value costs in the row store: its PropRecord + the overflow chain.
fn rowstore_string_bytes(s: &str) -> usize {
    let blocks = s.len().div_ceil(HEAP_PAYLOAD).max(1);
    PROP_RECORD + blocks * HEAP_BLOCK
}

/// A pure integer mixer (matches the generators' SplitMix64 family — deterministic, no clock).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn pct(after: usize, before: usize) -> f64 {
    if before == 0 { 0.0 } else { before as f64 / after.max(1) as f64 }
}

fn report_col(name: &str, rows: usize, rowstore: usize, columnar: usize) {
    println!(
        "  {name:<22} rows={rows:>8}  row_store={rowstore:>12} B  columnar={columnar:>11} B  ratio={:>7.1}x",
        pct(columnar, rowstore)
    );
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(100_000);

    println!("== columnar_footprint — row-store vs columnar property column footprint (n={n}) ==");

    // ---- IoT Reading columns (the time-series cold-tier showcase, rmp #332) ----
    println!("\nIoT :Reading {{sensor, seq, ts, value}}  (sensor fleet = 64, tick = 250ms):");
    const EPOCH_MS: i64 = 1_781_000_000_000;
    const TICK_MS: i64 = 250;
    let seq: Vec<i64> = (0..n as i64).collect();
    let ts: Vec<i64> = (0..n as i64).map(|i| EPOCH_MS + i * TICK_MS).collect();
    let mut rng = Rng(0x1234_5678);
    let mut v = 20.0f64;
    let value: Vec<f64> = (0..n)
        .map(|_| {
            // slow random walk in [~18, ~22], the documented slow-sensor-drift shape
            let step = ((rng.next() % 21) as f64 - 10.0) * 0.01;
            v = (v + step).clamp(18.0, 22.0);
            v
        })
        .collect();
    let sensor: Vec<Vec<u8>> = (0..n).map(|i| format!("s-{}", i % 64).into_bytes()).collect();

    let seq_rs = n * PROP_RECORD;
    let ts_rs = n * PROP_RECORD;
    let value_rs = n * PROP_RECORD;
    let sensor_rs: usize = sensor
        .iter()
        .map(|s| rowstore_string_bytes(std::str::from_utf8(s).unwrap()))
        .sum();

    let seq_c = integer::encode_i64(&seq).len();
    let ts_c = integer::encode_i64(&ts).len();
    let value_c = gorilla::encode(&value).len();
    let sensor_c = dictionary::encode(&sensor).len();

    report_col("seq:int (monotonic)", n, seq_rs, seq_c);
    report_col("ts:int (cadence)", n, ts_rs, ts_c);
    report_col("value:float (drift)", n, value_rs, value_c);
    report_col("sensor:string (64)", n, sensor_rs, sensor_c);
    let iot_rs = seq_rs + ts_rs + value_rs + sensor_rs;
    let iot_c = seq_c + ts_c + value_c + sensor_c;
    report_col("IoT TOTAL", n, iot_rs, iot_c);

    // ---- Social columns (the bulk/analytical-scan case, rmp #327/#329) ----
    println!("\nSocial :USER {{id, name, registered}}  (id = 24-hex unique; name from a pool):");
    let names_pool: Vec<&str> = vec![
        "Ana Silva", "João Costa", "Maria Santos", "Pedro Sousa", "Rita Oliveira", "Tiago Ferreira",
        "Sofia Martins", "Bruno Almeida", "Inês Pereira", "Miguel Rodrigues", "Carla Gomes",
        "Hugo Lopes", "Beatriz Marques", "André Carvalho", "Mariana Dias", "Diogo Pinto",
    ];
    let mut rng2 = Rng(0xABCD_EF01);
    let id: Vec<Vec<u8>> = (0..n)
        .map(|_| format!("{:024x}", rng2.next() & 0xFFFF_FFFF_FFFF).into_bytes())
        .collect();
    let name: Vec<Vec<u8>> = (0..n)
        .map(|_| names_pool[(rng2.next() as usize) % names_pool.len()].as_bytes().to_vec())
        .collect();
    let registered: Vec<i64> = (0..n as i64).map(|i| EPOCH_MS - i * 3_600_000).collect();

    let id_rs: usize = id.iter().map(|s| rowstore_string_bytes(std::str::from_utf8(s).unwrap())).sum();
    let name_rs: usize = name.iter().map(|s| rowstore_string_bytes(std::str::from_utf8(s).unwrap())).sum();
    let reg_rs = n * PROP_RECORD;
    let id_c = dictionary::encode(&id).len();
    let name_c = dictionary::encode(&name).len();
    let reg_c = integer::encode_i64(&registered).len();
    report_col("id:string (unique)", n, id_rs, id_c);
    report_col("name:string (pool=16)", n, name_rs, name_c);
    report_col("registered:int", n, reg_rs, reg_c);
    let soc_rs = id_rs + name_rs + reg_rs;
    let soc_c = id_c + name_c + reg_c;
    report_col("USER TOTAL", n, soc_rs, soc_c);

    println!("\nNotes:");
    println!("  - row_store = PROP_RECORD(46B) per value + 83B/48B overflow blocks for strings (audit-verified).");
    println!("  - columnar = graphus-columnar encoded blob (lossless, round-trip-exact).");
    println!("  - unique-id columns barely compress (expected: dictionary ~= raw for unique values);");
    println!("    the dramatic wins are monotonic ints (delta), slow floats (Gorilla), low-cardinality strings (dict).");
}
