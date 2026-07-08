//! Ferrite 5G NR physical layer.
//!
//! Implemented from 3GPP TS 38.211 (physical channels & modulation),
//! TS 38.212 (multiplexing & channel coding), and TS 38.213 (control
//! procedures). Milestone 1 covers the downlink cell-search / synchronization
//! path: SSB detection via PSS/SSS, then MIB decode from the PBCH.

pub mod coding;
pub mod numerology;
pub mod ofdm;
pub mod pdcch;
pub mod pdsch;
pub mod pdsch_params;
pub mod sequence;
pub mod sync;

pub use numerology::Numerology;
pub use ofdm::Ofdm;
