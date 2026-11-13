//! 5G NAS (TS 24.501) for a standalone UE.
//!
//! * [`ie`]: TS 24.007 information-element toolkit (reader/writer, optional
//!   IE iterator that skips unknown IEs) and [`NasError`].
//! * [`mm`] / [`sm`]: 5GMM and 5GSM message codecs with typed structs.
//! * [`security`]: NAS security context (TS 33.501 §6.4), NEA2/NIA2 framing,
//!   5G-AKA with SQN management and AUTS resynchronisation.
//! * [`milenage`]: MILENAGE f1..f5, f1*, f5* and the 5G key hierarchy.
//! * [`ue`]: the [`NasUe`] 5GMM/5GSM state machine.
//! * [`msgs`]: the legacy hand-rolled encoders that are the byte-exact
//!   compatibility baseline against the qcore 5G core.
#![forbid(unsafe_code)]

pub mod ie;
pub mod milenage;
pub mod mm;
pub mod msgs;
pub mod security;
pub mod sm;
pub mod ue;

pub use ie::NasError;
pub use mm::{Guti, Plmn, Snssai, Tai, UeSecurityCapability};
pub use security::NasSecurityContext;
pub use sm::PduSessionType;
pub use ue::{MmState, NasConfig, NasEvent, NasUe, PduSession, SmState, UeIdentity};
