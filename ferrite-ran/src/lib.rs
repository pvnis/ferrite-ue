//! RAN parameter tables and arithmetic from 3GPP TS 38.211–38.214 that every
//! layer may need — MCS tables, transport block sizes, DM-RS symbol
//! positions and antenna-port tables, PRACH configuration tables and
//! occasion enumeration, RIV coding, default TDRA tables, SRS bandwidth
//! tables. Pure functions over plain data: no DSP, no I/O, no state.
//!
//! `ferrite-phy` (signal processing) and `ferrite-fapi` (the PHY↔MAC
//! interface) both build on this crate, so the MAC and RRC can reason about
//! grants and configuration without linking the DSP library.

#![forbid(unsafe_code)]

pub mod codebook;
pub mod dmrs;
pub mod mcs;
pub mod prach_config;
pub mod prach_tables;
pub mod riv;
pub mod srs;
pub mod ssb;
pub mod tbs;
pub mod tdra;
