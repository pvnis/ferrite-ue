//! Ferrite UE L1 — the slot engine between the radio and MAC.
//!
//! * [`fapi`]: the PHY ↔ MAC interface (FAPI-style messages).
//! * [`config`]: the PHY configuration delivered by CONFIG.request.
//! * [`rt`], [`stream`]: real-time plumbing (queues, injection table, buffered radio stream).
//!
//! The engine itself (sync, PDCCH monitoring, PDSCH/HARQ receive, UL placement)
//! lives in the remaining modules.

// The PHY↔MAC interface and the PHY configuration are `ferrite-fapi`;
// re-exported under their historical paths.
pub use ferrite_fapi as fapi;
pub use ferrite_fapi::config;

pub(crate) mod cell;
pub(crate) mod dl;
pub mod engine;
pub(crate) mod resolve;
pub(crate) mod ul;
pub mod radio;
pub(crate) mod rt;
pub mod stream;
pub(crate) mod timing;
