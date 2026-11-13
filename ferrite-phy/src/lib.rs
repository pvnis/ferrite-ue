//! Ferrite 5G NR physical layer numerics.
//!
//! Implemented from 3GPP TS 38.211 (physical channels & modulation),
//! TS 38.212 (multiplexing & channel coding), TS 38.213 (control procedures)
//! and TS 38.214 (data procedures). Pure functions over slices: no threads, no
//! I/O, no cell state beyond the arguments. Generalised over numerology
//! (`mu` 0/1 for FR1) and sample rate.

pub mod coding;
pub mod coreset0;
pub mod csi;
pub mod dmrs;
pub mod mcs;
pub mod numerology;
pub mod ofdm;
pub mod pdcch;
pub mod pdsch;
pub mod pdsch_params;
pub mod prach;
pub mod prach_config;
pub mod prach_tables;
pub mod pucch;
pub mod pusch;
pub mod sequence;
pub mod sync;

pub use numerology::Numerology;
pub use ofdm::Ofdm;
