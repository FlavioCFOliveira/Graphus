//! The spatial **point** value class (`04-technical-design.md` §7.2; `rmp` task #73).
//!
//! openCypher (and the Neo4j/Bolt ecosystem it interoperates with) models a *spatial point* as a
//! value carrying a **coordinate reference system** (CRS) plus two or three `f64` coordinates. Four
//! CRSs are defined, each with a fixed numeric **SRID** (Spatial Reference System Identifier), and a
//! point is 2D or 3D depending on its CRS:
//!
//! | CRS name | SRID | dims | coordinate names |
//! | --- | --- | --- | --- |
//! | `cartesian` | 7203 | 2 | `x`, `y` |
//! | `cartesian-3d` | 9157 | 3 | `x`, `y`, `z` |
//! | `wgs-84` | 4326 | 2 | `longitude` (= `x`), `latitude` (= `y`) |
//! | `wgs-84-3d` | 4979 | 3 | `longitude`, `latitude`, `height` (= `z`) |
//!
//! (Source: the openCypher spatial CIP and the Neo4j spatial documentation; the SRID values are the
//! OGC/EPSG identifiers Neo4j adopts and the Bolt `Point2D`/`Point3D` structures carry verbatim.)
//!
//! # Why decomposed `f64` coordinates (like the temporal types)
//!
//! Mirroring [`crate::value::temporal`], a [`Point`] stores its CRS discriminant and a small,
//! **fixed-width** array of `f64` coordinates rather than an opaque blob, so:
//!
//! - the storage record codec ([`graphus_storage::valenc`]) and the index key codec
//!   ([`graphus_index::keycodec`]) can lay the components out most-significant-first and round-trip
//!   every bit; and
//! - Cypher's component-wise point semantics (`p.x`, `p.longitude`, equality within a CRS, a total
//!   order across CRSs) are directly representable.
//!
//! The actual calendar/great-circle intelligence (constructors from a property map, `distance()`,
//! ISO/WKT rendering) lives in the query layer (`graphus_cypher::spatial_fns`), exactly as the
//! temporal *calc* lives in [`crate::temporal_calc`]; this module owns only the **storage-shaped
//! representation** plus its equality and ordering helpers, which the value model needs everywhere.
//!
//! # Equality and ordering (openCypher §Equality / §Orderability)
//!
//! - **Equality** ([`Point::value_eq`]): two points are equal **iff** they share the same CRS *and*
//!   every coordinate is equal. A cross-CRS comparison is never equal. (`NaN` coordinates make a
//!   point unequal to itself, like every IEEE-754 float — the Cypher `=` operator layers its
//!   three-valued `NaN` handling on top in `graphus_cypher::equality`.)
//! - **Ordering** ([`Point::total_cmp`], a total order): points order first by CRS (by SRID), then
//!   lexicographically by coordinate, using the same total `f64` key the rest of Graphus uses
//!   (`-0.0 < +0.0`, `NaN` largest). This makes the point order consistent between the Cypher
//!   orderability relation and the memcmp index key.

use std::cmp::Ordering;

/// A coordinate reference system: one of the four openCypher CRSs (`rmp` task #73).
///
/// The discriminant order (`Cartesian`, `Cartesian3D`, `Wgs84`, `Wgs84_3D`) is **not** the ordering
/// key — points order by [`Crs::srid`] so the order is stable against a future CRS being inserted in
/// the enum. Each variant maps to a fixed [`Crs::srid`] (the wire/SRID contract) and a fixed
/// dimensionality ([`Crs::dimensions`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Crs {
    /// 2D Cartesian, SRID 7203, coordinates `(x, y)`.
    Cartesian,
    /// 3D Cartesian, SRID 9157, coordinates `(x, y, z)`.
    Cartesian3D,
    /// 2D geographic WGS-84, SRID 4326, coordinates `(longitude, latitude)`.
    Wgs84,
    /// 3D geographic WGS-84, SRID 4979, coordinates `(longitude, latitude, height)`.
    Wgs84_3D,
}

impl Crs {
    /// The SRID (Spatial Reference System Identifier) of this CRS — the OGC/EPSG number the Bolt
    /// `Point2D`/`Point3D` wire structures carry and the Cypher `point.srid` accessor returns.
    #[must_use]
    pub const fn srid(self) -> i64 {
        match self {
            Self::Cartesian => 7203,
            Self::Cartesian3D => 9157,
            Self::Wgs84 => 4326,
            Self::Wgs84_3D => 4979,
        }
    }

    /// The CRS for a given SRID, or [`None`] for an SRID Graphus does not model.
    #[must_use]
    pub const fn from_srid(srid: i64) -> Option<Self> {
        match srid {
            7203 => Some(Self::Cartesian),
            9157 => Some(Self::Cartesian3D),
            4326 => Some(Self::Wgs84),
            4979 => Some(Self::Wgs84_3D),
            _ => None,
        }
    }

    /// The canonical lower-case CRS name (`point.crs` accessor; `point({crs: …})` argument).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cartesian => "cartesian",
            Self::Cartesian3D => "cartesian-3d",
            Self::Wgs84 => "wgs-84",
            Self::Wgs84_3D => "wgs-84-3d",
        }
    }

    /// The CRS for a canonical name (case-insensitive), or [`None`] if unrecognised.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "cartesian" => Some(Self::Cartesian),
            "cartesian-3d" => Some(Self::Cartesian3D),
            "wgs-84" => Some(Self::Wgs84),
            "wgs-84-3d" => Some(Self::Wgs84_3D),
            _ => None,
        }
    }

    /// The number of coordinates a point in this CRS carries (`2` or `3`).
    #[must_use]
    pub const fn dimensions(self) -> usize {
        match self {
            Self::Cartesian | Self::Wgs84 => 2,
            Self::Cartesian3D | Self::Wgs84_3D => 3,
        }
    }

    /// Whether this CRS is geographic (WGS-84) rather than planar (Cartesian); geographic CRSs use a
    /// great-circle (haversine) `distance`, Cartesian ones the Euclidean distance.
    #[must_use]
    pub const fn is_geographic(self) -> bool {
        matches!(self, Self::Wgs84 | Self::Wgs84_3D)
    }

    /// The single-byte on-disk discriminant (frozen format, `rmp` task #73): the storage and index
    /// codecs persist this byte, so the mapping must never change. Bytes `4..` are reserved.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Cartesian => 0,
            Self::Cartesian3D => 1,
            Self::Wgs84 => 2,
            Self::Wgs84_3D => 3,
        }
    }

    /// Decodes a single-byte discriminant, or [`None`] for an unknown (reserved/future) byte so a
    /// forward-incompatible image is rejected rather than silently mis-decoded.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Cartesian),
            1 => Some(Self::Cartesian3D),
            2 => Some(Self::Wgs84),
            3 => Some(Self::Wgs84_3D),
            _ => None,
        }
    }
}

/// A spatial **point**: a CRS plus its 2 or 3 `f64` coordinates (openCypher; `rmp` task #73).
///
/// The coordinates are stored in a fixed `[f64; 3]` with the third slot unused (left `0.0`) for a 2D
/// CRS, so the type is `Copy` and fixed-width — the storage/index codecs persist exactly
/// [`Crs::dimensions`] coordinates. Construct one through [`Point::new_2d`] / [`Point::new_3d`] (which
/// pin the CRS dimensionality) and read its components through the accessors.
#[derive(Debug, Clone, Copy)]
pub struct Point {
    /// The coordinate reference system.
    pub crs: Crs,
    /// The coordinates, `coords[0..crs.dimensions()]` significant; the unused 3D slot is `0.0`.
    coords: [f64; 3],
}

impl Point {
    /// A 2D point in `crs` with coordinates `(x, y)`.
    ///
    /// # Panics
    /// Panics if `crs` is 3D (`Cartesian3D` / `Wgs84_3D`) — a programming error: a 2D constructor
    /// must be paired with a 2D CRS. The query-layer constructor validates user input *before* it
    /// reaches here, so this only ever fires on an internal mistake.
    #[must_use]
    pub fn new_2d(crs: Crs, x: f64, y: f64) -> Self {
        assert_eq!(crs.dimensions(), 2, "new_2d requires a 2D CRS");
        Self {
            crs,
            coords: [x, y, 0.0],
        }
    }

    /// A 3D point in `crs` with coordinates `(x, y, z)`.
    ///
    /// # Panics
    /// Panics if `crs` is 2D (`Cartesian` / `Wgs84`) — see [`Point::new_2d`].
    #[must_use]
    pub fn new_3d(crs: Crs, x: f64, y: f64, z: f64) -> Self {
        assert_eq!(crs.dimensions(), 3, "new_3d requires a 3D CRS");
        Self {
            crs,
            coords: [x, y, z],
        }
    }

    /// Builds a point from a CRS and a coordinate slice, validating the slice length against the
    /// CRS dimensionality. Returns [`None`] on a length mismatch (the storage/wire decoders use this
    /// to reject a malformed image rather than panic).
    #[must_use]
    pub fn from_crs_coords(crs: Crs, coords: &[f64]) -> Option<Self> {
        if coords.len() != crs.dimensions() {
            return None;
        }
        let mut c = [0.0_f64; 3];
        c[..coords.len()].copy_from_slice(coords);
        Some(Self { crs, coords: c })
    }

    /// The number of significant coordinates (`2` or `3`), i.e. `self.crs.dimensions()`.
    #[must_use]
    pub fn dimensions(&self) -> usize {
        self.crs.dimensions()
    }

    /// The significant coordinates, length [`Point::dimensions`].
    #[must_use]
    pub fn coords(&self) -> &[f64] {
        &self.coords[..self.crs.dimensions()]
    }

    /// The `x` coordinate (= `longitude` for WGS-84).
    #[must_use]
    pub fn x(&self) -> f64 {
        self.coords[0]
    }

    /// The `y` coordinate (= `latitude` for WGS-84).
    #[must_use]
    pub fn y(&self) -> f64 {
        self.coords[1]
    }

    /// The `z` coordinate (= `height` for WGS-84), or [`None`] for a 2D point.
    #[must_use]
    pub fn z(&self) -> Option<f64> {
        (self.crs.dimensions() == 3).then(|| self.coords[2])
    }

    /// Cypher point **equality**: same CRS and equal coordinates (openCypher §Equality).
    ///
    /// A cross-CRS comparison is `false`. Uses ordinary IEEE-754 `==` per coordinate (so `-0.0`
    /// equals `+0.0` and a `NaN` coordinate is never equal); the three-valued `NaN`/`null` rules of
    /// the Cypher `=` operator are layered on in `graphus_cypher::equality`.
    #[must_use]
    pub fn value_eq(&self, other: &Self) -> bool {
        self.crs == other.crs && self.coords() == other.coords()
    }

    /// The Cypher orderability of two points (a **total** order, openCypher §Orderability).
    ///
    /// Orders by CRS (by [`Crs::srid`]) first, then lexicographically by coordinate using the total
    /// `f64` key ([`total_f64`]) so `-0.0 < +0.0` and `NaN` is the largest — bit-identical to the
    /// index key codec, which keeps the Cypher point order and the memcmp B+-tree order in agreement.
    ///
    /// Named `total_cmp` (not `cmp`) because it is **not** the `Ord` relation: it intentionally
    /// disagrees with [`Point::value_eq`] on a `NaN` coordinate (a total order needs `NaN == NaN`,
    /// while value equality needs `NaN != NaN`), so [`Point`] is deliberately not `Ord`.
    #[must_use]
    pub fn total_cmp(&self, other: &Self) -> Ordering {
        self.crs
            .srid()
            .cmp(&other.crs.srid())
            .then_with(|| lexicographic_total(self.coords(), other.coords()))
    }
}

/// Structural equality for [`Point`] is the Cypher value equality (same CRS and coordinates), so a
/// `Value::Point` derives `PartialEq` consistently with [`Point::value_eq`]. Note this makes a `NaN`
/// coordinate compare unequal to itself, exactly like the derived `PartialEq` on a struct holding an
/// `f64` — the three-valued Cypher `=` adds its `NaN` handling above this.
impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.value_eq(other)
    }
}

/// The Cypher orderability `Ordering` of two `f64`s: `-inf < … < -0.0 < +0.0 < … < +inf < NaN`.
///
/// Identical to `graphus_cypher::ordering::total_f64` and the index keycodec's monotonic key (the
/// three implementations agree by construction). Kept here so the `Point` order is self-contained in
/// the dependency-free core.
#[must_use]
pub fn total_f64(a: f64, b: f64) -> Ordering {
    fn mono(x: f64) -> u64 {
        if x.is_nan() {
            !0u64
        } else {
            let bits = x.to_bits();
            if bits & 0x8000_0000_0000_0000 != 0 {
                !bits
            } else {
                bits ^ 0x8000_0000_0000_0000
            }
        }
    }
    mono(a).cmp(&mono(b))
}

/// Lexicographic [`total_f64`] order over two equal-length coordinate slices (the slices share a CRS
/// by the time this is called, so they have equal length; a residual length difference, never
/// expected, breaks the tie by length so the order stays total).
fn lexicographic_total(a: &[f64], b: &[f64]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        match total_f64(*x, *y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crs_srid_and_name_round_trip() {
        for crs in [Crs::Cartesian, Crs::Cartesian3D, Crs::Wgs84, Crs::Wgs84_3D] {
            assert_eq!(Crs::from_srid(crs.srid()), Some(crs));
            assert_eq!(Crs::from_name(crs.name()), Some(crs));
            assert_eq!(Crs::from_name(&crs.name().to_uppercase()), Some(crs));
            assert_eq!(Crs::from_byte(crs.as_byte()), Some(crs));
        }
        // The exact SRID contract (the wire/index numbers).
        assert_eq!(Crs::Cartesian.srid(), 7203);
        assert_eq!(Crs::Cartesian3D.srid(), 9157);
        assert_eq!(Crs::Wgs84.srid(), 4326);
        assert_eq!(Crs::Wgs84_3D.srid(), 4979);
        assert!(Crs::from_srid(1).is_none());
        assert_eq!(Crs::from_name("nope"), None);
        assert_eq!(Crs::from_byte(99), None);
    }

    #[test]
    fn dimensions_and_geographic_flags() {
        assert_eq!(Crs::Cartesian.dimensions(), 2);
        assert_eq!(Crs::Cartesian3D.dimensions(), 3);
        assert_eq!(Crs::Wgs84.dimensions(), 2);
        assert_eq!(Crs::Wgs84_3D.dimensions(), 3);
        assert!(!Crs::Cartesian.is_geographic());
        assert!(Crs::Wgs84.is_geographic());
        assert!(Crs::Wgs84_3D.is_geographic());
    }

    #[test]
    fn accessors_expose_significant_coordinates() {
        let p2 = Point::new_2d(Crs::Cartesian, 1.0, 2.0);
        assert_eq!(p2.x(), 1.0);
        assert_eq!(p2.y(), 2.0);
        assert_eq!(p2.z(), None);
        assert_eq!(p2.coords(), &[1.0, 2.0]);
        assert_eq!(p2.dimensions(), 2);

        let p3 = Point::new_3d(Crs::Wgs84_3D, 10.0, 20.0, 30.0);
        assert_eq!(p3.x(), 10.0);
        assert_eq!(p3.y(), 20.0);
        assert_eq!(p3.z(), Some(30.0));
        assert_eq!(p3.coords(), &[10.0, 20.0, 30.0]);
    }

    #[test]
    fn from_crs_coords_validates_length() {
        assert!(Point::from_crs_coords(Crs::Cartesian, &[1.0, 2.0]).is_some());
        assert!(Point::from_crs_coords(Crs::Cartesian, &[1.0]).is_none());
        assert!(Point::from_crs_coords(Crs::Cartesian, &[1.0, 2.0, 3.0]).is_none());
        assert!(Point::from_crs_coords(Crs::Cartesian3D, &[1.0, 2.0, 3.0]).is_some());
        assert!(Point::from_crs_coords(Crs::Cartesian3D, &[1.0, 2.0]).is_none());
    }

    #[test]
    fn equality_requires_same_crs_and_coordinates() {
        let a = Point::new_2d(Crs::Cartesian, 1.0, 2.0);
        let b = Point::new_2d(Crs::Cartesian, 1.0, 2.0);
        let c = Point::new_2d(Crs::Cartesian, 1.0, 3.0);
        // A WGS-84 point with the *same numeric coordinates* is NOT equal to the Cartesian one.
        let d = Point::new_2d(Crs::Wgs84, 1.0, 2.0);
        assert!(a.value_eq(&b));
        assert_eq!(a, b);
        assert!(!a.value_eq(&c));
        assert!(!a.value_eq(&d));
        assert_ne!(a, d);
        // -0.0 == +0.0 per coordinate.
        let z1 = Point::new_2d(Crs::Cartesian, -0.0, 0.0);
        let z2 = Point::new_2d(Crs::Cartesian, 0.0, -0.0);
        assert!(z1.value_eq(&z2));
        // A NaN coordinate is never equal to itself (IEEE-754).
        let nan = Point::new_2d(Crs::Cartesian, f64::NAN, 0.0);
        assert!(!nan.value_eq(&nan));
    }

    #[test]
    fn ordering_is_by_crs_then_coordinates_and_total() {
        let cart = Point::new_2d(Crs::Cartesian, 5.0, 5.0); // SRID 7203
        let wgs = Point::new_2d(Crs::Wgs84, 0.0, 0.0); // SRID 4326 < 7203
        // Ordered by SRID first: WGS-84 (4326) before Cartesian (7203).
        assert_eq!(wgs.total_cmp(&cart), Ordering::Less);
        assert_eq!(cart.total_cmp(&wgs), Ordering::Greater);

        // Within a CRS, lexicographic by coordinate.
        let a = Point::new_2d(Crs::Cartesian, 1.0, 2.0);
        let b = Point::new_2d(Crs::Cartesian, 1.0, 3.0);
        let c = Point::new_2d(Crs::Cartesian, 2.0, 0.0);
        assert_eq!(a.total_cmp(&b), Ordering::Less);
        assert_eq!(b.total_cmp(&c), Ordering::Less);
        assert_eq!(a.total_cmp(&a), Ordering::Equal);

        // -0.0 < +0.0 in ordering (distinct from equality).
        let neg = Point::new_2d(Crs::Cartesian, -0.0, 0.0);
        let pos = Point::new_2d(Crs::Cartesian, 0.0, 0.0);
        assert_eq!(neg.total_cmp(&pos), Ordering::Less);

        // NaN is the largest coordinate.
        let nan = Point::new_2d(Crs::Cartesian, f64::NAN, 0.0);
        let big = Point::new_2d(Crs::Cartesian, f64::INFINITY, 0.0);
        assert_eq!(big.total_cmp(&nan), Ordering::Less);
    }
}
