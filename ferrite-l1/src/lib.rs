//! Ferrite UE L1 — the slot engine between the radio and MAC.
//!
//! * [`fapi`]: the PHY ↔ MAC interface (FAPI-style messages).
//! * [`config`]: the PHY configuration delivered by CONFIG.request.
//! * [`rt`], [`stream`]: real-time plumbing (queues, injection table, buffered radio stream).
//!
//! The engine itself (sync, PDCCH monitoring, PDSCH/HARQ receive, UL placement)
//! lives in the remaining modules.
// Signal-processing loops index several arrays (grids, offsets, masks) by the same
// symbol / subcarrier index; the iterator rewrite clippy suggests reads worse.
#![allow(clippy::needless_range_loop)]

// The PHY↔MAC interface and the PHY configuration are `ferrite-fapi`;
// re-exported under their historical paths.
pub use ferrite_fapi as fapi;
pub use ferrite_fapi::config;

pub(crate) mod cell;
pub(crate) mod dl;
pub mod engine;
pub mod radio;
pub(crate) mod resolve;
pub(crate) mod rt;
pub mod stream;
pub(crate) mod timing;
pub(crate) mod ul;
