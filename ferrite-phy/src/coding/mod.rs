//! Channel coding for the physical layer (3GPP TS 38.212).
//!
//! Milestone 1 needs the BCH/PBCH chain: a 24-bit CRC and the polar code. Other
//! channels (PDCCH, PDSCH LDPC) build on this crate later.

pub mod bch;
pub mod crc;
pub mod dci;
pub mod dlsch;
pub mod ldpc;
pub mod ldpc_tables;
pub mod polar;
pub mod ratematch;
pub mod tables;
