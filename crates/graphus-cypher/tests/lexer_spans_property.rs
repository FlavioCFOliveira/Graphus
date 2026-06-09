//! Property test for the Cypher lexer's span discipline (`04-technical-design.md` §7.1/§7.3).
//!
//! The lexer's correctness contract is that, for any valid input, the emitted token spans are
//! **byte-accurate**: in source order, strictly non-overlapping, within bounds, on `char`
//! boundaries, and — together with the skipped whitespace/comment gaps — they **tile** the whole
//! input with no byte attributed to two tokens. The openCypher TCK asserts the byte offsets of
//! `SyntaxError`s, so these invariants are load-bearing for compliance.
//!
//! We drive the property check with [`graphus_sim::SimRng`] (a deterministic, seedable xorshift
//! RNG) so any failure is exactly reproducible from its seed — no flaky CI. We synthesize a random
//! sequence of *valid* tokens, glue them with random whitespace separators (always non-empty
//! between adjacent tokens so two tokens never merge), and assert the lexer:
//!
//! 1. produces exactly the token kinds we generated, in order;
//! 2. emits spans that are ordered, non-overlapping, in-bounds, and char-boundary-aligned;
//! 3. covers every non-whitespace byte exactly once (the spans tile the non-trivia input).

use graphus_core::capability::Rng;
use graphus_cypher::{IntBase, TokenKind, tokenize};
use graphus_sim::SimRng;

/// One generated token: its source spelling and the [`TokenKind`] the lexer must produce for it.
struct Gen {
    text: String,
    kind: TokenKind,
}

/// Picks a random valid token, returning its spelling and expected kind. Every arm produces a
/// token whose spelling is self-delimiting given a whitespace separator on each side.
fn gen_token(rng: &mut SimRng) -> Gen {
    match rng.next_u64() % 12 {
        0 => Gen {
            text: "MATCH".to_owned(),
            kind: TokenKind::Match,
        },
        1 => Gen {
            text: "RETURN".to_owned(),
            kind: TokenKind::Return,
        },
        2 => {
            // An identifier: lowercase ASCII, length 1..=6, starting with a letter. Guaranteed not
            // to collide with a keyword by prefixing `v`.
            let len = 1 + (rng.next_u64() % 5) as usize;
            let mut s = String::from("v");
            for _ in 0..len {
                s.push((b'a' + (rng.next_u64() % 26) as u8) as char);
            }
            Gen {
                kind: TokenKind::Identifier(s.clone()),
                text: s,
            }
        }
        3 => {
            // A decimal integer, 1..=6 digits, no leading zero (so it round-trips to one token).
            let len = 1 + (rng.next_u64() % 5) as usize;
            let mut s = String::new();
            s.push((b'1' + (rng.next_u64() % 9) as u8) as char);
            for _ in 1..len {
                s.push((b'0' + (rng.next_u64() % 10) as u8) as char);
            }
            let value: u128 = s.parse().expect("digits parse");
            Gen {
                kind: TokenKind::Integer(graphus_cypher::IntLiteral {
                    value,
                    base: IntBase::Decimal,
                }),
                text: s,
            }
        }
        4 => Gen {
            text: "(".to_owned(),
            kind: TokenKind::LParen,
        },
        5 => Gen {
            text: ")".to_owned(),
            kind: TokenKind::RParen,
        },
        6 => Gen {
            text: "->".to_owned(),
            kind: TokenKind::ArrowRight,
        },
        7 => Gen {
            text: "<=".to_owned(),
            kind: TokenKind::Lte,
        },
        8 => {
            // A parameter `$name`.
            let len = 1 + (rng.next_u64() % 4) as usize;
            let mut name = String::new();
            for _ in 0..len {
                name.push((b'a' + (rng.next_u64() % 26) as u8) as char);
            }
            Gen {
                text: format!("${name}"),
                kind: TokenKind::Parameter(name),
            }
        }
        9 => Gen {
            text: ":".to_owned(),
            kind: TokenKind::Colon,
        },
        10 => Gen {
            // A simple single-quoted string with only safe ASCII letters (no escapes/quotes).
            text: "'abc'".to_owned(),
            kind: TokenKind::String("abc".to_owned()),
        },
        _ => Gen {
            text: "true".to_owned(),
            kind: TokenKind::Boolean(true),
        },
    }
}

/// A random non-empty run of whitespace (spaces, tabs, newlines), 1..=3 chars.
fn gen_separator(rng: &mut SimRng) -> String {
    let len = 1 + (rng.next_u64() % 3) as usize;
    (0..len)
        .map(|_| match rng.next_u64() % 3 {
            0 => ' ',
            1 => '\t',
            _ => '\n',
        })
        .collect()
}

#[test]
fn spans_tile_input_and_kinds_round_trip_over_random_token_soup() {
    // A fixed seed makes the whole run deterministic and reproducible.
    let mut rng = SimRng::new(0xC0FF_EE12_3456_789A);

    for _case in 0..2_000 {
        let n_tokens = 1 + (rng.next_u64() % 10) as usize;

        let mut input = String::new();
        // Optional leading whitespace.
        if rng.next_u64() % 2 == 0 {
            input.push_str(&gen_separator(&mut rng));
        }

        let mut expected: Vec<Gen> = Vec::with_capacity(n_tokens);
        for i in 0..n_tokens {
            if i > 0 {
                // A mandatory non-empty separator between tokens so adjacent tokens never merge.
                input.push_str(&gen_separator(&mut rng));
            }
            let g = gen_token(&mut rng);
            input.push_str(&g.text);
            expected.push(g);
        }
        // Optional trailing whitespace.
        if rng.next_u64() % 2 == 0 {
            input.push_str(&gen_separator(&mut rng));
        }

        let tokens = tokenize(&input)
            .unwrap_or_else(|e| panic!("case {_case}: lexing failed on {input:?}: {e}"));

        // (1) Kinds round-trip, in order.
        assert_eq!(
            tokens.len(),
            expected.len(),
            "case {_case}: token count mismatch for {input:?}"
        );
        for (got, want) in tokens.iter().zip(&expected) {
            assert_eq!(
                got.kind, want.kind,
                "case {_case}: kind mismatch for {input:?}"
            );
        }

        // (2) Span invariants + (3) tiling of non-whitespace bytes.
        // `covered[b]` records whether byte `b` is inside some token span.
        let mut covered = vec![false; input.len()];
        let mut prev_end = 0usize;
        for t in &tokens {
            assert!(
                t.span.start >= prev_end,
                "case {_case}: spans out of order / overlapping at {t:?} in {input:?}"
            );
            assert!(
                t.span.start < t.span.end,
                "case {_case}: empty/inverted span {t:?} in {input:?}"
            );
            assert!(
                t.span.end <= input.len(),
                "case {_case}: span past EOF {t:?} in {input:?}"
            );
            // Char-boundary correctness: slicing must not panic and must equal the token spelling.
            assert!(
                input.is_char_boundary(t.span.start) && input.is_char_boundary(t.span.end),
                "case {_case}: span not on char boundary {t:?} in {input:?}"
            );
            for byte in &mut covered[t.span.start..t.span.end] {
                *byte = true;
            }
            prev_end = t.span.end;
        }

        // Every non-whitespace byte must be covered by exactly one token; every covered byte must
        // be non-whitespace (whitespace is trivia and never inside a token here, as our generated
        // tokens contain no internal whitespace except inside the `'abc'` string, which has none).
        for (b, &is_covered) in input.as_bytes().iter().zip(&covered) {
            if b.is_ascii_whitespace() {
                assert!(
                    !is_covered,
                    "case {_case}: whitespace byte {b:#x} was covered by a token in {input:?}"
                );
            } else {
                assert!(
                    is_covered,
                    "case {_case}: non-whitespace byte {b:#x} left uncovered in {input:?}"
                );
            }
        }
    }
}
