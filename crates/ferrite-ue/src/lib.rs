//! Ferrite UE application layer: ties the PHY to radio backends and (soon)
//! the protocol stack. Currently hosts bring-up tooling.

pub mod milenage;
pub mod nas;
pub mod rrc;
pub mod rt;
pub mod cellgroup;
pub mod sib1;
pub mod uper;
pub mod stream;
pub mod sync;
pub mod tun;
pub mod userplane;
