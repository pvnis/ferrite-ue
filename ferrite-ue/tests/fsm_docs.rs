//! The state diagrams in `docs/ARCHITECTURE.md` are generated from the
//! transition tables (`ferrite_common::fsm::mermaid`); this test fails when
//! a table changes without its diagram, and prints the block to paste.

// Test / development tool: panicking on a broken setup is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ferrite_common::fsm::{mermaid, Machine};

fn check<M: Machine>(doc: &str) -> Option<String> {
    let block = format!("```mermaid\n{}```", mermaid::<M>());
    (!doc.contains(&block))
        .then(|| format!("{} diagram out of date; expected:\n{block}\n", M::NAME))
}

#[test]
fn architecture_diagrams_match_the_tables() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ARCHITECTURE.md");
    let doc = std::fs::read_to_string(path).unwrap_or_default();
    let stale: Vec<String> = [
        check::<ferrite_l1::engine::CellPhaseMachine>(&doc),
        check::<ferrite_l1::engine::RlmMachine>(&doc),
        check::<ferrite_mac::RaMachine>(&doc),
        check::<ferrite_mac::SrMachine>(&doc),
        check::<ferrite_mac::TaMachine>(&doc),
        check::<ferrite_mac::DrxMachine>(&doc),
        check::<ferrite_rrc::machine::RrcMachine>(&doc),
        check::<ferrite_nas::machine::MmMachine>(&doc),
        check::<ferrite_nas::machine::CmMachine>(&doc),
        check::<ferrite_nas::machine::SmMachine>(&doc),
        check::<ferrite_mac::harq::DlHarqMachine>(&doc),
        check::<ferrite_mac::harq::UlHarqMachine>(&doc),
        check::<ferrite_rlc::AmTxMachine>(&doc),
        check::<ferrite_ue::machine::SecMachine>(&doc),
        check::<ferrite_ue::machine::ConnMachine>(&doc),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(stale.is_empty(), "{}", stale.join("\n"));
}
