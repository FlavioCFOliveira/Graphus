//! `graphus-cypher` — Cypher parse, plan and execute pipeline for Graphus (targets the openCypher
//! TCK).
//!
//! This crate hosts the compile/execute pipeline (`04-technical-design.md` §7.1). Two parts exist
//! today:
//!
//! - The **lexer** ([`lexer`]) — the pipeline's front door — turns query text into a token stream
//!   with byte-accurate source spans (`04 §7.1`). Lexer errors are the compile-time `SyntaxError`
//!   class with precise positions (`04 §7.3`), as the openCypher TCK asserts error offsets.
//! - The **Cypher value-model semantics** ([`ordering`], [`equality`], [`equivalence`],
//!   [`ternary`]) — the meaning of comparing, ordering, and de-duplicating [`graphus_core::Value`]s
//!   (`04 §7.2`, §7.6). Every rule there is taken **verbatim from the openCypher
//!   comparability/orderability/equality CIP** (CIP2016-06-14), the source the TCK enforces.
//!
//! The parser that consumes the lexer's token stream is the next sub-task (`04 §7.1`).
//!
//! # The four value-model operations (they are genuinely different)
//!
//! A recurring source of TCK failures is conflating these; Graphus keeps them as four separate,
//! independently-tested operations:
//!
//! | Operation | Module | Result | `null` | `NaN` | `-0.0` vs `+0.0` |
//! |-----------|--------|--------|--------|-------|------------------|
//! | Ordering (`ORDER BY`) | [`ordering`] | total order | largest | largest number | distinct (`-0.0 < +0.0`) |
//! | Equality (`=`) | [`equality`] | `Ternary` | propagates (`→ NULL`) | `NaN = NaN → FALSE` | equal |
//! | Membership (`IN`) | [`equality::is_in`] | `Ternary` | propagates | never matches | equal |
//! | Equivalence (`DISTINCT`/grouping) | [`equivalence`] | `bool` | `null ≡ null → true` | `NaN ≡ NaN → true` | equal |
//!
//! Boolean predicates combine via three-valued (Kleene) logic in [`ternary`].
//!
//! # Ascending global order (CIP2016-06-14 §Orderability), verbatim
//!
//! ```text
//! MAP < NODE < RELATIONSHIP < LIST < PATH < {temporals} < STRING < BOOLEAN < NUMBER < NaN < null
//! ```
//!
//! with `{temporals}` ascending `ZonedDateTime < LocalDateTime < Date < ZonedTime < LocalTime <
//! Duration`. (Note the openCypher quirk `STRING < BOOLEAN < NUMBER`.)
//!
//! # Cross-validation against the index
//!
//! For the index-encodable value classes, [`ordering::cmp_values`] is proven byte-for-byte
//! identical to `graphus_index::keycodec`'s encoded order by `tests/ordering_vs_keycodec.rs`. The
//! two are written independently, so the agreement guarantees a memcmp B+-tree returns rows in
//! exactly Cypher order.
//!
//! # Temporal values
//!
//! The temporal value classes are present as additive variants of [`graphus_core::Value`]
//! ([`Date`](graphus_core::Date), [`LocalTime`](graphus_core::LocalTime),
//! [`ZonedTime`](graphus_core::ZonedTime), [`LocalDateTime`](graphus_core::LocalDateTime),
//! [`ZonedDateTime`](graphus_core::ZonedDateTime), [`Duration`](graphus_core::Duration)), at
//! nanosecond resolution, and are fully ordered, compared, grouped, and index-encoded here and in
//! `graphus-index`.
//!
//! # Deferred
//!
//! The **structural** value classes — `Node`, `Relationship`, and `Path` — are **deferred to the
//! executor sub-task**: they are not yet variants of [`graphus_core::Value`] (they require entity
//! identity and the graph store). Their orderability rank slots are reserved in [`ordering`] (ranks
//! 1, 2 and 4) so they slot in without renumbering. The `Point` (spatial) class is likewise future
//! work. Until then, this crate's operations are total over the value classes that *do* exist.
#![forbid(unsafe_code)]

pub mod equality;
pub mod equivalence;
pub mod lexer;
pub mod ordering;
pub mod ternary;

pub use equality::{equals, is_in, not_equals};
pub use equivalence::equivalent;
pub use lexer::{IntBase, IntLiteral, LexError, LexErrorKind, Span, Token, TokenKind, tokenize};
pub use ordering::cmp_values;
pub use ternary::Ternary;
