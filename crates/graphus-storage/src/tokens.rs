//! Token / dictionary store: three bidirectional `id(u32) <-> name` namespaces
//! (`04-technical-design.md` §2.6).
//!
//! Labels, relationship types, and property keys each get an independent, append-only
//! dictionary. Tokens are small and fully cached in memory ([`TokenStore`]); creation is
//! WAL-logged so a label/type/key created during a write recovers atomically with that write
//! (`04 §2.6`). The persistent encoding ([`encode`](TokenStore::encode) /
//! [`decode`](TokenStore::decode)) lets [`crate::store`] log a redo image of the whole table and
//! replay it on recovery.
//!
//! Ids are dense and assigned monotonically from `0` within each namespace. Names are unique
//! within a namespace; interning an existing name returns its existing id.

use std::collections::HashMap;

use graphus_core::error::{GraphusError, Result};

/// The three token namespaces (`04 §2.6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// Node label names.
    Label,
    /// Relationship-type names.
    RelType,
    /// Property-key names.
    PropKey,
}

impl Namespace {
    /// All namespaces, in their stable persistence order.
    pub const ALL: [Namespace; 3] = [Namespace::Label, Namespace::RelType, Namespace::PropKey];

    fn tag(self) -> u8 {
        match self {
            Namespace::Label => 0,
            Namespace::RelType => 1,
            Namespace::PropKey => 2,
        }
    }
}

/// A single bidirectional `id <-> name` dictionary for one namespace.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TokenTable {
    by_id: Vec<String>,
    by_name: HashMap<String, u32>,
}

impl TokenTable {
    /// Interns `name`, returning its id (existing or newly assigned). The bool is `true` when a
    /// new id was created (so the caller knows the table changed and must be WAL-logged).
    fn intern(&mut self, name: &str) -> Result<(u32, bool)> {
        if let Some(&id) = self.by_name.get(name) {
            return Ok((id, false));
        }
        let id = u32::try_from(self.by_id.len())
            .map_err(|_| GraphusError::Storage("token namespace exhausted".to_owned()))?;
        self.by_id.push(name.to_owned());
        self.by_name.insert(name.to_owned(), id);
        Ok((id, true))
    }

    fn name(&self, id: u32) -> Option<&str> {
        self.by_id.get(id as usize).map(String::as_str)
    }

    fn id(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// The in-memory token store holding all three namespaces (`04 §2.6`).
///
/// Fully cached; persisted by [`encode`](Self::encode) and rebuilt by [`decode`](Self::decode)
/// during recovery.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TokenStore {
    labels: TokenTable,
    rel_types: TokenTable,
    prop_keys: TokenTable,
}

impl TokenStore {
    /// An empty token store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&self, ns: Namespace) -> &TokenTable {
        match ns {
            Namespace::Label => &self.labels,
            Namespace::RelType => &self.rel_types,
            Namespace::PropKey => &self.prop_keys,
        }
    }

    fn table_mut(&mut self, ns: Namespace) -> &mut TokenTable {
        match ns {
            Namespace::Label => &mut self.labels,
            Namespace::RelType => &mut self.rel_types,
            Namespace::PropKey => &mut self.prop_keys,
        }
    }

    /// Interns `name` in `ns`, returning `(id, created)` where `created` is `true` if a new id was
    /// assigned (i.e. the store changed and the caller must persist/log it).
    ///
    /// # Errors
    /// Returns a storage error if the namespace's `u32` id space is exhausted.
    pub fn intern(&mut self, ns: Namespace, name: &str) -> Result<(u32, bool)> {
        self.table_mut(ns).intern(name)
    }

    /// The name for `id` in `ns`, if present.
    #[must_use]
    pub fn name(&self, ns: Namespace, id: u32) -> Option<&str> {
        self.table(ns).name(id)
    }

    /// The id for `name` in `ns`, if present.
    #[must_use]
    pub fn id(&self, ns: Namespace, name: &str) -> Option<u32> {
        self.table(ns).id(name)
    }

    /// The number of tokens in `ns`.
    #[must_use]
    pub fn len(&self, ns: Namespace) -> usize {
        self.table(ns).len()
    }

    /// Whether `ns` holds no tokens.
    #[must_use]
    pub fn is_empty(&self, ns: Namespace) -> bool {
        self.table(ns).len() == 0
    }

    /// Serialises the whole token store to a self-describing byte image (used as a WAL redo
    /// image and to rebuild the store on recovery).
    ///
    /// Layout per namespace: `tag(1) | count(u32) | [ len(u32) | utf8-bytes ]*`, in
    /// [`Namespace::ALL`] order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for ns in Namespace::ALL {
            let t = self.table(ns);
            out.push(ns.tag());
            out.extend_from_slice(&(t.len() as u32).to_le_bytes());
            for name in &t.by_id {
                out.extend_from_slice(&(name.len() as u32).to_le_bytes());
                out.extend_from_slice(name.as_bytes());
            }
        }
        out
    }

    /// Rebuilds a token store from an image produced by [`encode`](Self::encode).
    ///
    /// # Errors
    /// Returns a storage error if the image is truncated or not valid UTF-8.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut store = Self::new();
        let mut cur = 0usize;
        for expected in Namespace::ALL {
            let tag = *bytes
                .get(cur)
                .ok_or_else(|| GraphusError::Storage("token image truncated (tag)".to_owned()))?;
            cur += 1;
            if tag != expected.tag() {
                return Err(GraphusError::Storage(format!(
                    "token image namespace out of order: got tag {tag}"
                )));
            }
            let count = read_u32(bytes, &mut cur)?;
            let table = store.table_mut(expected);
            for _ in 0..count {
                let len = read_u32(bytes, &mut cur)? as usize;
                let end = cur
                    .checked_add(len)
                    .filter(|&e| e <= bytes.len())
                    .ok_or_else(|| {
                        GraphusError::Storage("token image truncated (name)".to_owned())
                    })?;
                let name = std::str::from_utf8(&bytes[cur..end])
                    .map_err(|_| GraphusError::Storage("token name not utf-8".to_owned()))?
                    .to_owned();
                cur = end;
                let id = u32::try_from(table.by_id.len())
                    .map_err(|_| GraphusError::Storage("token namespace exhausted".to_owned()))?;
                table.by_name.insert(name.clone(), id);
                table.by_id.push(name);
            }
        }
        Ok(store)
    }
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32> {
    let end = *cur + 4;
    if end > bytes.len() {
        return Err(GraphusError::Storage(
            "token image truncated (u32)".to_owned(),
        ));
    }
    let v = u32::from_le_bytes(bytes[*cur..end].try_into().expect("4-byte slice"));
    *cur = end;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_assigns_dense_monotonic_ids() {
        let mut t = TokenStore::new();
        assert_eq!(t.intern(Namespace::Label, "Person").unwrap(), (0, true));
        assert_eq!(t.intern(Namespace::Label, "Movie").unwrap(), (1, true));
        // Re-interning is idempotent and reports "not created".
        assert_eq!(t.intern(Namespace::Label, "Person").unwrap(), (0, false));
    }

    #[test]
    fn namespaces_are_independent() {
        let mut t = TokenStore::new();
        let (lbl, _) = t.intern(Namespace::Label, "X").unwrap();
        let (typ, _) = t.intern(Namespace::RelType, "X").unwrap();
        let (key, _) = t.intern(Namespace::PropKey, "X").unwrap();
        assert_eq!((lbl, typ, key), (0, 0, 0)); // same name, separate id spaces
        assert_eq!(t.name(Namespace::Label, 0), Some("X"));
        assert_eq!(t.id(Namespace::RelType, "X"), Some(0));
    }

    #[test]
    fn lookup_misses_return_none() {
        let t = TokenStore::new();
        assert_eq!(t.name(Namespace::Label, 0), None);
        assert_eq!(t.id(Namespace::PropKey, "nope"), None);
        assert!(t.is_empty(Namespace::Label));
    }

    #[test]
    fn encode_decode_round_trips_all_namespaces() {
        let mut t = TokenStore::new();
        t.intern(Namespace::Label, "Person").unwrap();
        t.intern(Namespace::Label, "Company").unwrap();
        t.intern(Namespace::RelType, "KNOWS").unwrap();
        t.intern(Namespace::PropKey, "name").unwrap();
        t.intern(Namespace::PropKey, "age").unwrap();

        let image = t.encode();
        let back = TokenStore::decode(&image).unwrap();

        for ns in Namespace::ALL {
            assert_eq!(back.len(ns), t.len(ns));
        }
        assert_eq!(back.name(Namespace::Label, 1), Some("Company"));
        assert_eq!(back.id(Namespace::RelType, "KNOWS"), Some(0));
        assert_eq!(back.id(Namespace::PropKey, "age"), Some(1));
    }

    #[test]
    fn decode_rejects_a_truncated_image() {
        let mut t = TokenStore::new();
        t.intern(Namespace::Label, "Person").unwrap();
        let mut image = t.encode();
        image.truncate(image.len() - 1); // lose the last name byte
        assert!(TokenStore::decode(&image).is_err());
    }
}
