//! Ferrite UE application layer: ties the PHY to radio backends and (soon)
//! the protocol stack. Currently hosts bring-up tooling.

pub mod milenage;
pub mod nas;
pub mod rrc;
pub mod stream;
pub mod sync;
pub mod tun;
pub mod userplane;
