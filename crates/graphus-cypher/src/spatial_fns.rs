//! Spatial **point** functions for the evaluator: the `point()` constructor, `distance()` /
//! `point.distance()`, and the point component accessors (`rmp` task #73; `04 §7.2`).
//!
//! This is the spatial counterpart of [`crate::temporal_fns`]: the pure value-shaped types and the
//! storage/wire codecs live in `graphus_core::value::spatial`, while the openCypher *function*
//! semantics — building a point from a property map, the Cartesian/great-circle distance, and the
//! `.x`/`.longitude`/`.crs`/… accessors — live here, where the evaluator can reach them.
//!
//! # `point(map)` (openCypher / Neo4j spatial)
//!
//! The argument is a **map** whose keys select the CRS and supply the coordinates:
//!
//! - Cartesian keys `x`, `y` (and optional `z`) → `cartesian` / `cartesian-3d`.
//! - Geographic keys `longitude`, `latitude` (and optional `height`) → `wgs-84` / `wgs-84-3d`.
//!   `x`/`y`/`z` are accepted as synonyms for `longitude`/`latitude`/`height`.
//! - An explicit `crs` (a name) or `srid` (a number) **overrides** the inferred CRS; the supplied
//!   key set must then match that CRS's dimensionality.
//!
//! Missing required coordinates, or a coordinate that is not a number, raise the openCypher runtime
//! error (an `InvalidArgumentValue`-class `TypeError` here). A `null` argument yields `null`.
//!
//! # `distance(p1, p2)` (and `p1.distance(p2)` / `point.distance(p1, p2)`)
//!
//! Defined only for two points **in the same CRS** (else `null`, the openCypher rule). For a
//! Cartesian CRS it is the Euclidean distance (2D or 3D); for a geographic (WGS-84) CRS it is the
//! great-circle distance in **metres** via the haversine formula on a **spherical** Earth of mean
//! radius [`EARTH_MEAN_RADIUS_METRES`] (the model Neo4j documents for `point.distance` on WGS-84).
//! A `null` operand makes the result `null`.

use graphus_core::Value;
use graphus_core::value::spatial::{Crs, Point};

use crate::eval::EvalError;

/// The mean radius of the Earth in metres (IUGG mean radius `R₁ = (2a + b) / 3 ≈ 6 371 008.8 m`).
///
/// This is the spherical-Earth radius the haversine great-circle distance uses for WGS-84 points.
/// Neo4j's `point.distance` documents a spherical model with a mean Earth radius; pinning the IUGG
/// mean radius keeps the result within the small tolerance the spatial scenarios assert against
/// known city-pair distances.
pub const EARTH_MEAN_RADIUS_METRES: f64 = 6_371_008.8;

fn type_err(context: impl Into<String>) -> EvalError {
    EvalError::TypeError {
        context: context.into(),
    }
}

// =================================================================================================
// Constructor: point(map)
// =================================================================================================

/// Builds a [`Value::Point`] from a `point()` argument (`rmp` task #73). A `null` argument yields
/// `null`; a non-map argument is a `TypeError`.
///
/// # Errors
/// [`EvalError::TypeError`] for a non-map argument, a missing/duplicate-class coordinate set, a
/// non-numeric coordinate, or an unknown explicit `crs`/`srid`.
pub(crate) fn construct_point(arg: &Value) -> Result<Value, EvalError> {
    if arg.is_null() {
        return Ok(Value::Null);
    }
    let Value::Map(entries) = arg else {
        return Err(type_err("point() requires a map argument"));
    };

    // Look up a coordinate by any of its accepted key names (case-insensitive), returning the first
    // present one as an `f64` (a non-number is a TypeError).
    let coord = |names: &[&str]| -> Result<Option<f64>, EvalError> {
        for (k, v) in entries {
            if names.iter().any(|n| k.eq_ignore_ascii_case(n)) {
                return as_coord(v).map(Some);
            }
        }
        Ok(None)
    };
    let has_key = |names: &[&str]| -> bool {
        entries
            .iter()
            .any(|(k, _)| names.iter().any(|n| k.eq_ignore_ascii_case(n)))
    };

    // An explicit CRS override (`crs` name or `srid` number) wins over inference.
    let explicit_crs = explicit_crs(entries)?;

    // Geographic if longitude/latitude are present (or the override is geographic), else Cartesian.
    let geographic = explicit_crs.map_or_else(
        || has_key(&["longitude"]) || has_key(&["latitude"]),
        Crs::is_geographic,
    );

    // Gather the coordinates. `x`/`y`/`z` are synonyms for `longitude`/`latitude`/`height`.
    let (cx, cy, cz) = if geographic {
        (
            coord(&["longitude", "x"])?,
            coord(&["latitude", "y"])?,
            coord(&["height", "z"])?,
        )
    } else {
        (coord(&["x"])?, coord(&["y"])?, coord(&["z"])?)
    };

    let (x, y) = match (cx, cy) {
        (Some(x), Some(y)) => (x, y),
        _ => {
            return Err(type_err(
                "point() requires both x/longitude and y/latitude coordinates",
            ));
        }
    };

    // Decide the CRS: an explicit override (validated against the present dimensions), else inferred
    // from the geographic flag and the presence of a third coordinate.
    let crs = match explicit_crs {
        Some(c) => {
            let want_3d = c.dimensions() == 3;
            if want_3d != cz.is_some() {
                return Err(type_err(format!(
                    "point() coordinates do not match the requested CRS {}",
                    c.name()
                )));
            }
            c
        }
        None => match (geographic, cz.is_some()) {
            (false, false) => Crs::Cartesian,
            (false, true) => Crs::Cartesian3D,
            (true, false) => Crs::Wgs84,
            (true, true) => Crs::Wgs84_3D,
        },
    };

    let point = match cz {
        Some(z) => Point::new_3d(crs, x, y, z),
        None => Point::new_2d(crs, x, y),
    };
    Ok(Value::Point(point))
}

/// The explicit CRS override from a `crs`/`srid` key, or [`None`] if neither is present. An unknown
/// name/SRID is a `TypeError`.
fn explicit_crs(entries: &[(String, Value)]) -> Result<Option<Crs>, EvalError> {
    for (k, v) in entries {
        if k.eq_ignore_ascii_case("crs") {
            let Value::String(name) = v else {
                return Err(type_err("point() `crs` must be a string"));
            };
            return Crs::from_name(name)
                .map(Some)
                .ok_or_else(|| type_err(format!("point() has an unknown CRS name {name:?}")));
        }
        if k.eq_ignore_ascii_case("srid") {
            let srid = match v {
                Value::Integer(i) => *i,
                Value::Float(f) if f.fract() == 0.0 => *f as i64,
                _ => return Err(type_err("point() `srid` must be an integer")),
            };
            return Crs::from_srid(srid)
                .map(Some)
                .ok_or_else(|| type_err(format!("point() has an unknown SRID {srid}")));
        }
    }
    Ok(None)
}

/// Coerces a coordinate value to `f64`: a number is itself; anything else is a `TypeError`.
fn as_coord(v: &Value) -> Result<f64, EvalError> {
    match v {
        Value::Integer(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        other => Err(type_err(format!(
            "point() coordinate must be a number, got {other:?}"
        ))),
    }
}

// =================================================================================================
// distance(p1, p2)
// =================================================================================================

/// The Cypher `distance(p1, p2)` (a.k.a. `point.distance`): the distance between two points in the
/// **same** CRS, or `null` if they differ in CRS or either operand is null (`rmp` task #73).
///
/// Cartesian → Euclidean (2D/3D); WGS-84 → great-circle haversine in metres
/// ([`EARTH_MEAN_RADIUS_METRES`]).
///
/// # Errors
/// [`EvalError::TypeError`] if either operand is a non-null, non-point value (openCypher raises a
/// type error for `distance('a', point(...))`).
pub(crate) fn distance(a: &Value, b: &Value) -> Result<Value, EvalError> {
    if a.is_null() || b.is_null() {
        return Ok(Value::Null);
    }
    let (Value::Point(p1), Value::Point(p2)) = (a, b) else {
        return Err(type_err("distance() requires two point arguments"));
    };
    // Different CRSs → null (openCypher: distance is undefined across reference systems).
    if p1.crs != p2.crs {
        return Ok(Value::Null);
    }
    let d = if p1.crs.is_geographic() {
        haversine_metres(p1, p2)
    } else {
        euclidean(p1, p2)
    };
    Ok(Value::Float(d))
}

/// The Euclidean distance between two Cartesian points (2D or 3D); the points share a CRS, hence the
/// same dimensionality.
fn euclidean(p1: &Point, p2: &Point) -> f64 {
    p1.coords()
        .iter()
        .zip(p2.coords().iter())
        .map(|(a, b)| {
            let d = a - b;
            d * d
        })
        .sum::<f64>()
        .sqrt()
}

/// The great-circle distance in metres between two WGS-84 points, via the haversine formula on a
/// sphere of radius [`EARTH_MEAN_RADIUS_METRES`].
///
/// For a 3D WGS-84 pair the height difference is combined with the surface arc as the hypotenuse
/// (`sqrt(arc² + Δheight²)`), the documented Neo4j behaviour for `point.distance` on `wgs-84-3d`.
fn haversine_metres(p1: &Point, p2: &Point) -> f64 {
    // x = longitude, y = latitude (degrees).
    let lon1 = p1.x().to_radians();
    let lat1 = p1.y().to_radians();
    let lon2 = p2.x().to_radians();
    let lat2 = p2.y().to_radians();

    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let sin_dlat = (dlat / 2.0).sin();
    let sin_dlon = (dlon / 2.0).sin();
    let h = sin_dlat * sin_dlat + lat1.cos() * lat2.cos() * sin_dlon * sin_dlon;
    // `h` is in [0, 1] in exact arithmetic; clamp to absorb tiny FP excess so `asin`/`sqrt` stay real.
    let arc = 2.0 * EARTH_MEAN_RADIUS_METRES * h.clamp(0.0, 1.0).sqrt().asin();

    match (p1.z(), p2.z()) {
        (Some(z1), Some(z2)) => {
            let dh = z2 - z1;
            (arc * arc + dh * dh).sqrt()
        }
        _ => arc,
    }
}

// =================================================================================================
// Component accessors (point.x, point.crs, …)
// =================================================================================================

/// The value of a point **component accessor** `point.<key>` (`rmp` task #73), or [`None`] if `key`
/// is not a point component. Recognised keys (case-insensitive):
///
/// - `x` / `longitude` → the first coordinate; `y` / `latitude` → the second; `z` / `height` → the
///   third (or `null` for a 2D point).
/// - `crs` → the CRS name (a string); `srid` → the SRID (an integer).
///
/// Returning [`None`] (rather than `Value::Null`) lets the caller distinguish "not a point accessor"
/// (fall through to the generic missing-property rule) from "a valid accessor that is null" (the 2D
/// `z`/`height` case).
#[must_use]
pub(crate) fn component(point: &Point, key: &str) -> Option<Value> {
    let lower = key.to_ascii_lowercase();
    Some(match lower.as_str() {
        "x" | "longitude" => Value::Float(point.x()),
        "y" | "latitude" => Value::Float(point.y()),
        "z" | "height" => point.z().map_or(Value::Null, Value::Float),
        "crs" => Value::String(point.crs.name().to_owned()),
        "srid" => Value::Integer(point.crs.srid()),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }
    fn f(x: f64) -> Value {
        Value::Float(x)
    }
    fn i(n: i64) -> Value {
        Value::Integer(n)
    }

    #[test]
    fn point_constructs_cartesian_2d_and_3d() {
        let v = construct_point(&p(&[("x", f(1.0)), ("y", f(2.0))])).unwrap();
        assert_eq!(v, Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0)));
        let v3 = construct_point(&p(&[("x", f(1.0)), ("y", f(2.0)), ("z", f(3.0))])).unwrap();
        assert_eq!(
            v3,
            Value::Point(Point::new_3d(Crs::Cartesian3D, 1.0, 2.0, 3.0))
        );
        // Integer coordinates are accepted (coerced to float).
        let vi = construct_point(&p(&[("x", i(1)), ("y", i(2))])).unwrap();
        assert_eq!(vi, Value::Point(Point::new_2d(Crs::Cartesian, 1.0, 2.0)));
    }

    #[test]
    fn point_constructs_wgs84_from_lon_lat() {
        let v = construct_point(&p(&[("longitude", f(-8.61)), ("latitude", f(41.15))])).unwrap();
        assert_eq!(v, Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15)));
        let v3 = construct_point(&p(&[
            ("longitude", f(1.0)),
            ("latitude", f(2.0)),
            ("height", f(3.0)),
        ]))
        .unwrap();
        assert_eq!(
            v3,
            Value::Point(Point::new_3d(Crs::Wgs84_3D, 1.0, 2.0, 3.0))
        );
    }

    #[test]
    fn explicit_crs_and_srid_override() {
        // An explicit srid forces WGS-84 even from x/y keys.
        let v = construct_point(&p(&[("x", f(1.0)), ("y", f(2.0)), ("srid", i(4326))])).unwrap();
        assert_eq!(v, Value::Point(Point::new_2d(Crs::Wgs84, 1.0, 2.0)));
        // An explicit crs name likewise.
        let v2 = construct_point(&p(&[
            ("x", f(1.0)),
            ("y", f(2.0)),
            ("crs", Value::String("wgs-84".into())),
        ]))
        .unwrap();
        assert_eq!(v2, Value::Point(Point::new_2d(Crs::Wgs84, 1.0, 2.0)));
    }

    #[test]
    fn point_errors_on_missing_coords_and_unknown_crs() {
        assert!(construct_point(&p(&[("x", f(1.0))])).is_err()); // no y
        assert!(construct_point(&p(&[("x", f(1.0)), ("y", Value::String("z".into()))])).is_err());
        assert!(construct_point(&p(&[("x", f(1.0)), ("y", f(2.0)), ("srid", i(9999))])).is_err());
        // A null argument yields null, not an error.
        assert_eq!(construct_point(&Value::Null).unwrap(), Value::Null);
        // A non-map argument is a type error.
        assert!(construct_point(&Value::Integer(1)).is_err());
    }

    #[test]
    fn cartesian_distance_is_euclidean() {
        let a = Value::Point(Point::new_2d(Crs::Cartesian, 0.0, 0.0));
        let b = Value::Point(Point::new_2d(Crs::Cartesian, 3.0, 4.0));
        assert_eq!(distance(&a, &b).unwrap(), Value::Float(5.0));
        // 3D.
        let a3 = Value::Point(Point::new_3d(Crs::Cartesian3D, 0.0, 0.0, 0.0));
        let b3 = Value::Point(Point::new_3d(Crs::Cartesian3D, 2.0, 3.0, 6.0));
        assert_eq!(distance(&a3, &b3).unwrap(), Value::Float(7.0));
    }

    #[test]
    fn cross_crs_distance_is_null_and_null_operands_propagate() {
        let cart = Value::Point(Point::new_2d(Crs::Cartesian, 0.0, 0.0));
        let wgs = Value::Point(Point::new_2d(Crs::Wgs84, 0.0, 0.0));
        assert_eq!(distance(&cart, &wgs).unwrap(), Value::Null);
        assert_eq!(distance(&cart, &Value::Null).unwrap(), Value::Null);
        assert_eq!(distance(&Value::Null, &cart).unwrap(), Value::Null);
        // A non-point operand is a type error.
        assert!(distance(&cart, &Value::Integer(1)).is_err());
    }

    #[test]
    fn wgs84_distance_matches_known_city_pair_within_tolerance() {
        // London (51.5074 N, 0.1278 W) to Paris (48.8566 N, 2.3522 E). The great-circle distance is
        // ~343.5 km; assert within 1 km (covers the spherical-model approximation and FP).
        let london = Value::Point(Point::new_2d(Crs::Wgs84, -0.1278, 51.5074));
        let paris = Value::Point(Point::new_2d(Crs::Wgs84, 2.3522, 48.8566));
        let Value::Float(d) = distance(&london, &paris).unwrap() else {
            panic!("expected a float distance");
        };
        assert!(
            (d - 343_556.0).abs() < 1_000.0,
            "London–Paris great-circle distance was {d} m"
        );
        // Symmetric.
        let Value::Float(d2) = distance(&paris, &london).unwrap() else {
            panic!()
        };
        assert!((d - d2).abs() < 1e-6);
        // Zero distance to itself.
        assert_eq!(distance(&london, &london).unwrap(), Value::Float(0.0));
    }

    #[test]
    fn accessors_expose_components() {
        let cart = Point::new_3d(Crs::Cartesian3D, 1.0, 2.0, 3.0);
        assert_eq!(component(&cart, "x"), Some(Value::Float(1.0)));
        assert_eq!(component(&cart, "y"), Some(Value::Float(2.0)));
        assert_eq!(component(&cart, "z"), Some(Value::Float(3.0)));
        assert_eq!(component(&cart, "srid"), Some(Value::Integer(9157)));
        assert_eq!(
            component(&cart, "crs"),
            Some(Value::String("cartesian-3d".to_owned()))
        );

        let wgs = Point::new_2d(Crs::Wgs84, 10.0, 20.0);
        assert_eq!(component(&wgs, "longitude"), Some(Value::Float(10.0)));
        assert_eq!(component(&wgs, "latitude"), Some(Value::Float(20.0)));
        // A 2D point's z/height is a present-but-null accessor.
        assert_eq!(component(&wgs, "height"), Some(Value::Null));
        assert_eq!(component(&wgs, "z"), Some(Value::Null));
        // An unrecognised key is None (not a point accessor).
        assert_eq!(component(&wgs, "nope"), None);
        // Accessors are case-insensitive.
        assert_eq!(component(&wgs, "LONGITUDE"), Some(Value::Float(10.0)));
    }
}
