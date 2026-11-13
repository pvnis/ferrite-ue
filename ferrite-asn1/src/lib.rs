//! Clean-room TS 38.331 UPER codecs for the Ferrite 5G NR UE.
//!
//! * [`uper`] — the X.691 unaligned-PER bit reader/writer and [`uper::DecodeError`].
//! * [`sib1`] — `SystemInformationBlockType1` decoding (structured, FDD and TDD).
//! * [`cellgroup`] / [`csi`] — `CellGroupConfig` (the dedicated MAC/PHY configuration).
//! * [`rrc`] — the DL/UL CCCH/DCCH messages, `RadioBearerConfig` and a minimal
//!   `UE-NR-Capability` encoder.
//! * [`meas`] — `MeasConfig` (decode) and `MeasResults` (encode) for measurement reporting.
//! * [`si`] — `SystemInformation` (SIB2/SIB3 structured, later SIBs raw).
//! * [`common`] — IEs shared by the above.
//!
//! The MIB is decoded in the PHY crate and is not in scope here.
#![forbid(unsafe_code)]

pub mod cellgroup;
pub mod common;
pub mod csi;
pub mod meas;
pub mod rrc;
pub mod si;
pub mod sib1;
pub mod uper;

pub use uper::{DecodeError, DecodeErrorKind, DecodeResult, SetupRelease};
