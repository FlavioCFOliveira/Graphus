//! `graphus-elle` binary — a thin self-test of the [`graphus_elle`] isolation checker.
//!
//! Runs the checker over a known-serializable and a known-cyclic history and prints the verdicts,
//! exiting non-zero if either verdict is wrong (a guard that the checker keeps its teeth).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use graphus_elle::{Op, Transaction, check};

fn main() -> ExitCode {
    let serial = vec![
        Transaction::committed(
            1,
            vec![Op::Append {
                key: "a".into(),
                val: 1,
            }],
        ),
        Transaction::committed(
            2,
            vec![
                Op::Read {
                    key: "a".into(),
                    observed: vec![1],
                },
                Op::Append {
                    key: "a".into(),
                    val: 2,
                },
            ],
        ),
    ];
    let skew = vec![
        Transaction::committed(
            1,
            vec![
                Op::Read {
                    key: "y".into(),
                    observed: vec![],
                },
                Op::Append {
                    key: "x".into(),
                    val: 1,
                },
            ],
        ),
        Transaction::committed(
            2,
            vec![
                Op::Read {
                    key: "x".into(),
                    observed: vec![],
                },
                Op::Append {
                    key: "y".into(),
                    val: 1,
                },
            ],
        ),
    ];

    let s = check(&serial);
    let w = check(&skew);
    println!("graphus-elle self-test: serial={s:?} write_skew={w:?}");

    if s.serializable && !w.serializable {
        ExitCode::SUCCESS
    } else {
        eprintln!("graphus-elle self-test FAILED: checker lost its teeth");
        ExitCode::FAILURE
    }
}
