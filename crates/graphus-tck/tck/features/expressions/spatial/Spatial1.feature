#
# Graphus-authored spatial conformance scenarios (rmp task #73).
#
# IMPORTANT — provenance: these scenarios are NOT part of the upstream openCypher TCK corpus
# (the pinned snapshot in ../../../PINNED.txt has no `expressions/spatial` directory — spatial
# point support was never standardised into the public openCypher feature set; it exists only in
# Neo4j's proprietary TCK). They are authored by the Graphus project to lock in the spatial
# semantics of `point()` / `distance()` / the point accessors / point equality / point orderability,
# mirroring the openCypher spatial CIP and the Neo4j spatial documentation. They run through the
# REAL engine via the same harness as the vendored corpus, so the ratchet they raise is a genuine,
# engine-verified gain — it is simply Graphus-authored coverage, transparently labelled here.
#
# To keep within the harness's value-comparison surface (which parses scalar / string / list / map /
# node / rel / path cells, but not a `point(...)` literal), every result cell below is a SCALAR
# DERIVED from a point — an accessor (`.x`, `.srid`, `.crs`), a `distance(...)` number, an equality
# boolean, or an ordering position — never a bare point literal. This asserts the spatial semantics
# end to end without inventing a point-literal rendering the comparator does not define.

#encoding: utf-8

Feature: Spatial1 - point() construction, accessors, distance, equality and ordering

  Scenario: [1] point() builds a 2D Cartesian point from x/y, read back via accessors
    Given any graph
    When executing query:
      """
      WITH point({x: 3, y: 4}) AS p
      RETURN p.x AS x, p.y AS y, p.srid AS srid, p.crs AS crs
      """
    Then the result should be, in any order:
      | x   | y   | srid | crs         |
      | 3.0 | 4.0 | 7203 | 'cartesian' |
    And no side effects

  Scenario: [2] point() builds a 3D Cartesian point when z is present
    Given any graph
    When executing query:
      """
      WITH point({x: 1, y: 2, z: 3}) AS p
      RETURN p.x AS x, p.y AS y, p.z AS z, p.srid AS srid, p.crs AS crs
      """
    Then the result should be, in any order:
      | x   | y   | z   | srid | crs            |
      | 1.0 | 2.0 | 3.0 | 9157 | 'cartesian-3d' |
    And no side effects

  Scenario: [3] point() builds a 2D WGS-84 point from longitude/latitude
    Given any graph
    When executing query:
      """
      WITH point({longitude: -8.61, latitude: 41.15}) AS p
      RETURN p.longitude AS lon, p.latitude AS lat, p.srid AS srid, p.crs AS crs
      """
    Then the result should be, in any order:
      | lon   | lat   | srid | crs      |
      | -8.61 | 41.15 | 4326 | 'wgs-84' |
    And no side effects

  Scenario: [4] point() builds a 3D WGS-84 point when height is present
    Given any graph
    When executing query:
      """
      WITH point({longitude: 1, latitude: 2, height: 3}) AS p
      RETURN p.srid AS srid, p.crs AS crs, p.height AS h
      """
    Then the result should be, in any order:
      | srid | crs         | h   |
      | 4979 | 'wgs-84-3d' | 3.0 |
    And no side effects

  Scenario: [5] An explicit srid overrides the inferred CRS
    Given any graph
    When executing query:
      """
      WITH point({x: 1, y: 2, srid: 4326}) AS p
      RETURN p.srid AS srid, p.crs AS crs
      """
    Then the result should be, in any order:
      | srid | crs      |
      | 4326 | 'wgs-84' |
    And no side effects

  Scenario: [6] WGS-84 longitude is the x accessor and latitude is the y accessor
    Given any graph
    When executing query:
      """
      WITH point({longitude: 12.5, latitude: -7.25}) AS p
      RETURN p.x AS x, p.y AS y
      """
    Then the result should be, in any order:
      | x    | y     |
      | 12.5 | -7.25 |
    And no side effects

  Scenario: [7] The z accessor of a 2D point is null
    Given any graph
    When executing query:
      """
      RETURN point({x: 1, y: 2}).z AS z
      """
    Then the result should be, in any order:
      | z    |
      | null |
    And no side effects

  Scenario: [8] distance() between two Cartesian points is the Euclidean distance
    Given any graph
    When executing query:
      """
      RETURN distance(point({x: 0, y: 0}), point({x: 3, y: 4})) AS d
      """
    Then the result should be, in any order:
      | d   |
      | 5.0 |
    And no side effects

  Scenario: [9] distance() between two 3D Cartesian points is the 3D Euclidean distance
    Given any graph
    When executing query:
      """
      RETURN distance(point({x: 0, y: 0, z: 0}), point({x: 2, y: 3, z: 6})) AS d
      """
    Then the result should be, in any order:
      | d   |
      | 7.0 |
    And no side effects

  Scenario: [10] distance() across different CRSs is null
    Given any graph
    When executing query:
      """
      RETURN distance(point({x: 0, y: 0}), point({longitude: 0, latitude: 0})) AS d
      """
    Then the result should be, in any order:
      | d    |
      | null |
    And no side effects

  Scenario: [11] distance() with a null operand is null
    Given any graph
    When executing query:
      """
      RETURN distance(point({x: 0, y: 0}), null) AS d
      """
    Then the result should be, in any order:
      | d    |
      | null |
    And no side effects

  Scenario: [12] A point equals another point with the same CRS and coordinates
    Given any graph
    When executing query:
      """
      RETURN point({x: 1, y: 2}) = point({x: 1, y: 2}) AS eq
      """
    Then the result should be, in any order:
      | eq   |
      | true |
    And no side effects

  Scenario: [13] Points with the same coordinates but different CRS are not equal
    Given any graph
    When executing query:
      """
      RETURN point({x: 1, y: 2}) = point({longitude: 1, latitude: 2}) AS eq
      """
    Then the result should be, in any order:
      | eq    |
      | false |
    And no side effects

  Scenario: [14] Points with different coordinates are not equal
    Given any graph
    When executing query:
      """
      RETURN point({x: 1, y: 2}) = point({x: 1, y: 3}) AS eq
      """
    Then the result should be, in any order:
      | eq    |
      | false |
    And no side effects

  Scenario: [15] A point property round-trips through a node and its accessors
    Given an empty graph
    And having executed:
      """
      CREATE (:City {loc: point({longitude: -8.61, latitude: 41.15})})
      """
    When executing query:
      """
      MATCH (c:City)
      RETURN c.loc.longitude AS lon, c.loc.latitude AS lat, c.loc.srid AS srid
      """
    Then the result should be, in any order:
      | lon   | lat   | srid |
      | -8.61 | 41.15 | 4326 |
    And no side effects

  Scenario: [16] Points order by CRS (srid) then by coordinates under ORDER BY
    Given any graph
    When executing query:
      """
      UNWIND [
        point({longitude: 5, latitude: 5}),
        point({x: 1, y: 2}),
        point({x: 1, y: 1})
      ] AS p
      WITH p
      ORDER BY p
      RETURN p.srid AS srid, p.x AS x, p.y AS y
      """
    Then the result should be, in order:
      | srid | x   | y   |
      | 4326 | 5.0 | 5.0 |
      | 7203 | 1.0 | 1.0 |
      | 7203 | 1.0 | 2.0 |
    And no side effects

  Scenario: [17] point.distance is an alias for distance
    Given any graph
    When executing query:
      """
      RETURN point.distance(point({x: 0, y: 0}), point({x: 6, y: 8})) AS d
      """
    Then the result should be, in any order:
      | d    |
      | 10.0 |
    And no side effects
