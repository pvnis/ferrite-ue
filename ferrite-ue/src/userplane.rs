//! User plane above the default DRB: a TUN device when one is configured,
//! otherwise the built-in ICMP echo client (the `--ping` probe) and echo
//! responder, so a bare UE still answers pings and can probe the core.

use crate::config::UeConfig;
use crate::ip;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// What the built-in probe reports.
#[derive(Clone, Debug, PartialEq)]
pub enum UserPlaneEvent {
    PingReply { seq: u16, rtt_ms: f64 },
    PingDone { sent: u32, received: u32 },
}

pub struct UserPlane {
    tun_name: Option<String>,
    netns: Option<String>,
    tun: Option<std::fs::File>,
    ip: Option<[u8; 4]>,
    // Built-in probe.
    ping_count: u32,
    ping_rounds: u32,
    ping_interval: Duration,
    ping_round_gap: Duration,
    ping_target: [u8; 4],
    ping_id: u16,
    ping_seq: u16,
    ping_sent: Vec<Instant>,
    ping_recv: u32,
    next_ping: Instant,
    ping_done: bool,
    result: Option<(u32, u32)>,
    events: Vec<UserPlaneEvent>,
}

impl UserPlane {
    pub fn new(cfg: &UeConfig) -> Self {
        Self {
            tun_name: cfg.tun.clone(),
            netns: cfg.netns.clone(),
            tun: None,
            ip: None,
            ping_count: cfg.ping_count,
            ping_rounds: cfg.ping_rounds.max(1),
            ping_interval: Duration::from_millis(cfg.ping_interval_ms),
            ping_round_gap: Duration::from_secs(cfg.ping_round_gap_s),
            ping_target: cfg.ping_target,
            ping_id: 0xfe11,
            ping_seq: 0,
            ping_sent: Vec::new(),
            ping_recv: 0,
            next_ping: Instant::now(),
            ping_done: false,
            result: None,
            events: Vec::new(),
        }
    }

    /// The UE's IPv4 address while a PDU session is up.
    pub fn ip(&self) -> Option<[u8; 4]> {
        self.ip
    }

    /// `(sent, received)` once the built-in probe has finished.
    pub fn ping_result(&self) -> Option<(u32, u32)> {
        self.result
    }

    pub fn take_events(&mut self) -> Vec<UserPlaneEvent> {
        std::mem::take(&mut self.events)
    }

    /// A PDU session came up with `ip`: open the TUN or arm the probe.
    pub fn session_up(&mut self, ip: [u8; 4]) {
        self.ip = Some(ip);
        self.next_ping = Instant::now() + Duration::from_millis(500);
        let Some(name) = self.tun_name.clone() else { return };
        match crate::tun::open_tun(&name) {
            Ok(f) => {
                if let Err(e) = crate::tun::configure_tun(&name, ip, 1400, self.netns.as_deref()) {
                    log::warn!("TUN {name}: configuration failed: {e}");
                }
                self.tun = Some(f);
                log::info!("TUN {name} up");
            }
            Err(e) => log::warn!("TUN {name}: {e}"),
        }
    }

    /// The PDU session is gone (released, or the UE deregistered).
    pub fn session_down(&mut self) {
        if self.tun.take().is_some() {
            log::info!("TUN closed");
        }
        self.ip = None;
    }

    /// Uplink IP packets due now: what the TUN delivered plus a probe echo
    /// request when one is scheduled.
    pub fn poll_uplink(&mut self) -> Vec<Vec<u8>> {
        let mut pkts = Vec::new();
        if let Some(t) = self.tun.as_mut() {
            let mut buf = [0u8; 2048];
            for _ in 0..16 {
                match t.read(&mut buf) {
                    Ok(n) if n > 0 => pkts.push(buf[..n].to_vec()),
                    _ => break,
                }
            }
            return pkts;
        }
        let (Some(ip), true) = (self.ip, self.ping_count > 0) else { return pkts };
        let total = self.ping_count * self.ping_rounds;
        if u32::from(self.ping_seq) < total && Instant::now() >= self.next_ping {
            pkts.push(ip::ipv4_icmp_echo_request(ip, self.ping_target, self.ping_id, self.ping_seq, b"ferrite-ping"));
            self.ping_sent.push(Instant::now());
            self.ping_seq += 1;
            let round_done = u32::from(self.ping_seq) % self.ping_count == 0 && u32::from(self.ping_seq) < total;
            let wait = if round_done && !self.ping_round_gap.is_zero() {
                log::info!("ping round {} of {} done; next round in {} s", u32::from(self.ping_seq) / self.ping_count, self.ping_rounds, self.ping_round_gap.as_secs());
                self.ping_round_gap
            } else {
                self.ping_interval
            };
            self.next_ping = Instant::now() + wait;
        }
        if !self.ping_done && u32::from(self.ping_seq) >= total && self.ping_sent.last().is_some_and(|t| t.elapsed() > Duration::from_secs(2)) {
            self.ping_done = true;
            self.result = Some((u32::from(self.ping_seq), self.ping_recv));
            self.events.push(UserPlaneEvent::PingDone { sent: u32::from(self.ping_seq), received: self.ping_recv });
        }
        pkts
    }

    /// A downlink IP packet: to the TUN, or handled by the built-in stack.
    /// Returns a packet to send back (an echo reply), if any.
    pub fn on_downlink(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        if let Some(t) = self.tun.as_mut() {
            if let Err(e) = t.write(pkt) {
                log::warn!("TUN write failed: {e}");
            }
            return None;
        }
        if let Some(reply) = ip::ipv4_icmp_echo_reply_for(pkt) {
            log::info!("echo request from {}.{}.{}.{}: replying", pkt[12], pkt[13], pkt[14], pkt[15]);
            return Some(reply);
        }
        if let Some(r) = ip::parse_ipv4_icmp_echo_reply(pkt) {
            if let Some(t0) = self.ping_sent.get(r.seq as usize) {
                let rtt = t0.elapsed().as_secs_f64() * 1e3;
                self.ping_recv += 1;
                log::info!("ping reply seq={} rtt={rtt:.1} ms", r.seq);
                self.events.push(UserPlaneEvent::PingReply { seq: r.seq, rtt_ms: rtt });
            }
        }
        None
    }
}
