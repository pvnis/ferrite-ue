//! The state diagrams in `docs/ARCHITECTURE.md` are generated from the
//! transition tables (`ferrite_common::fsm::mermaid`); this test fails when
//! a table changes without its diagram, and prints the block to paste.

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
        check::<ferrite_rrc::machine::RrcMachine>(&doc),
        check::<ferrite_mac::RaMachine>(&doc),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(stale.is_empty(), "{}", stale.join("\n"));
}
