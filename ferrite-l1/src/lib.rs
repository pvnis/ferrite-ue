//! Ferrite UE L1 — the slot engine between the radio and MAC.
//!
//! * [`fapi`]: the PHY ↔ MAC interface (FAPI-style messages).
//! * [`config`]: the PHY configuration delivered by CONFIG.request.
//! * [`rt`], [`stream`]: real-time plumbing (queues, injection table, buffered radio stream).
//!
//! The engine itself (sync, PDCCH monitoring, PDSCH/HARQ receive, UL placement)
//! lives in the remaining modules.

pub mod cell;
pub mod config;
pub mod dl;
pub mod engine;
pub mod fapi;
pub mod resolve;
pub mod ul;
pub mod radio;
pub mod rt;
pub mod stream;
pub mod timing;
