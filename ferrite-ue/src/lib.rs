//! Ferrite UE application crate: configuration, the L2/L3 stack composition
//! behind the FAPI-style PHY interface, and OS plumbing (TUN, ICMP probe).

pub mod bearers;
pub mod config;
pub mod ip;
pub mod pcap;
pub mod stack;
pub mod tun;
pub mod userplane;
