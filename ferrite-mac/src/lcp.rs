//! Logical Channel Prioritisation (TS 38.321 §5.4.3.1): token buckets per
//! channel (PBR/BSD) and the two-round allocation.

use crate::LogicalChannelConfig;
use ferrite_common::SlotPoint;

#[derive(Clone, Debug)]
struct Bucket {
    cfg: LogicalChannelConfig,
    /// Bj in bytes (clamped to PBR·BSD).
    bj: i64,
    last: Option<SlotPoint>,
}

/// LCP state across grants.
#[derive(Clone, Debug, Default)]
pub struct Lcp {
    buckets: Vec<Bucket>,
}

impl Lcp {
    pub fn new(channels: &[LogicalChannelConfig]) -> Self {
        let mut buckets: Vec<Bucket> = channels.iter().map(|c| Bucket { cfg: *c, bj: 0, last: None }).collect();
        buckets.sort_by_key(|b| b.cfg.priority);
        Self { buckets }
    }

    pub fn channels(&self) -> impl Iterator<Item = &LogicalChannelConfig> {
        self.buckets.iter().map(|b| &b.cfg)
    }


    /// Advance the token buckets to `now` (§5.4.3.1: Bj += PBR × elapsed, capped).
    pub fn tick(&mut self, now: SlotPoint) {
        for b in &mut self.buckets {
            let elapsed_ms = b.last.map_or(0.0, |l| now.diff(&l).max(0) as f64 * now.numerology.slot_duration_us() / 1000.0);
            b.last = Some(now);
            if let Some(pbr) = b.cfg.pbr_bytes_per_ms {
                let cap = pbr as i64 * b.cfg.bsd_ms as i64;
                b.bj = (b.bj + (pbr as f64 * elapsed_ms) as i64).min(cap);
            } else {
                b.bj = i64::MAX / 4;
            }
        }
    }

    /// Allocate `budget` bytes of MAC SDU space across channels, given each
    /// channel's pending bytes (`pending(lcid)`), in two rounds: first up to Bj
    /// in priority order, then the remainder strictly by priority. Returns
    /// `(lcid, bytes)` allocations (bytes excludes MAC subheaders; the caller
    /// accounts for them by passing a budget net of headers).
    pub fn allocate(&mut self, budget: usize, pending: &mut dyn FnMut(u8) -> usize) -> Vec<(u8, usize)> {
        let mut left = budget;
        let mut alloc: Vec<(u8, usize)> = Vec::new();
        // Round 1: up to Bj.
        for b in &mut self.buckets {
            if left == 0 {
                break;
            }
            let want = pending(b.cfg.lcid);
            let cap = if b.cfg.pbr_bytes_per_ms.is_some() { b.bj.max(0) as usize } else { usize::MAX };
            let take = want.min(cap).min(left);
            if take > 0 {
                alloc.push((b.cfg.lcid, take));
                left -= take;
                if b.cfg.pbr_bytes_per_ms.is_some() {
                    b.bj -= take as i64;
                }
            }
        }
        // Round 2: remaining data in priority order.
        for b in &self.buckets {
            if left == 0 {
                break;
            }
            let already = alloc.iter().find(|a| a.0 == b.cfg.lcid).map_or(0, |a| a.1);
            let want = pending(b.cfg.lcid).saturating_sub(already);
            let take = want.min(left);
            if take > 0 {
                if let Some(a) = alloc.iter_mut().find(|a| a.0 == b.cfg.lcid) {
                    a.1 += take;
                } else {
                    alloc.push((b.cfg.lcid, take));
                }
                left -= take;
            }
        }
        alloc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_and_pbr() {
        let chans = [
            LogicalChannelConfig { lcid: 4, priority: 8, pbr_bytes_per_ms: Some(8), bsd_ms: 100, lcg: 1, sr_id: None, sr_mask: false },
            LogicalChannelConfig { lcid: 1, priority: 1, pbr_bytes_per_ms: None, bsd_ms: 1000, lcg: 0, sr_id: None, sr_mask: false },
        ];
        let mut lcp = Lcp::new(&chans);
        let now = SlotPoint::new(ferrite_common::Numerology::KHZ30, 0, 0);
        lcp.tick(now);
        // SRB1 (prio 1, infinite PBR) gets served first; DRB gets what's left.
        let a = lcp.allocate(100, &mut |l| if l == 1 { 30 } else { 500 });
        assert_eq!(a, vec![(1, 30), (4, 70)]);
    }
}
