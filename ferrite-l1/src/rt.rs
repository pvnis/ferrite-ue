//! Concurrency runtime for the UE: the staged-pipeline plumbing that lets the
//! hard-real-time ZMQ/timeline thread stay responsive while the heavy DSP and the
//! protocol stack run on other threads (OCUDU's task-executor-with-queues pattern).
//!
//! This module holds the transport-agnostic building blocks — the typed messages that
//! flow between stages, the bounded queues that connect them (backpressure included),
//! and the [`InjectionTable`]
//! the timeline thread uses to place ready uplink waveforms at their absolute sample
//! positions. Wiring these into `run()` is done in later phases; here they are
//! self-contained and unit-tested.

use num_complex::Complex32;

/// An uplink waveform tagged with the absolute uplink sample position where it must be
/// injected. Produced by the TX-build stage, consumed by the timeline thread.
pub struct ReadyWaveform {
    pub pos: i64,
    pub samples: Vec<Complex32>,
    /// What this waveform is (PUSCH / ACK / SR / …) — audit-mode overlap reports only.
    pub tag: &'static str,
}

/// Collects ready uplink waveforms (produced asynchronously, possibly out of order) and
/// injects their samples into uplink blocks at absolute positions. Owned by the timeline
/// thread; replaces the inline `pend_*` + `place` logic in `run()`. Because the gNB
/// requests uplink in lockstep with the downlink it sends, "absolute position" is the
/// running uplink sample counter — a waveform whose position is already behind the
/// counter when it arrives has missed its deadline and is counted (and dropped).
#[derive(Default)]
pub struct InjectionTable {
    pending: Vec<(ReadyWaveform, usize)>,
    misses: u64,
    audit: bool,
    /// Recently retired waveform spans (pos, len, tag) — for overlap detection in audit mode.
    retired: Vec<(i64, usize, &'static str)>,
}

impl InjectionTable {
    pub fn new() -> Self {
        Self {
            audit: std::env::var_os("FERRITE_DRIFT").is_some(),
            ..Self::default()
        }
    }

    /// Queue a waveform for injection. `now` is the current uplink counter; if the
    /// waveform's whole span is already behind it, the ACK/grant it carries can no longer
    /// land in its slot — count a deadline miss (it is still queued but will be dropped
    /// on the next `fill`, contributing nothing).
    pub fn push(&mut self, wf: ReadyWaveform, now: i64) {
        if wf.pos + wf.samples.len() as i64 <= now {
            self.misses += 1;
        }
        if self.audit {
            if wf.pos < now {
                // Already partially behind the serve: the head of this waveform can never
                // be placed — the exact signature of a "partial waveform" at the receiver.
                eprintln!(
                    "[inj] LATE push pos={} len={} now={} behind={} samples",
                    wf.pos,
                    wf.samples.len(),
                    now,
                    now - wf.pos
                );
            }
            // Overlap check against everything still pending and recently retired: two
            // waveforms sharing samples garble each other at the receiver (last write wins
            // per sample) — the collision signature behind low-SINR CRC-KO uplinks.
            let (s, e) = (wf.pos, wf.pos + wf.samples.len() as i64);
            for (other, _) in &self.pending {
                let (os, oe) = (other.pos, other.pos + other.samples.len() as i64);
                if s < oe && os < e {
                    eprintln!(
                        "[inj] OVERLAP push {} [{s},{e}) vs pending {} [{os},{oe})",
                        wf.tag, other.tag
                    );
                }
            }
            for &(os, ol, otag) in &self.retired {
                let oe = os + ol as i64;
                if s < oe && os < e {
                    eprintln!("[inj] OVERLAP push {} [{s},{e}) vs RETIRED {} [{os},{oe}) (span already served)", wf.tag, otag);
                }
            }
        }
        self.pending.push((wf, 0));
    }

    /// Remove every pending waveform with `tag` — for waveforms that became stale after
    /// being queued (e.g. Msg3 pre-injections once contention resolution is won): an
    /// already-pushed waveform can't otherwise be unqueued, and it would garble whatever
    /// else lands in its slot (the fill is last-write-wins).
    pub fn retract(&mut self, tag: &str) {
        self.pending.retain(|(wf, _)| wf.tag != tag);
    }

    /// Place any queued samples that overlap the block `[base, base + block.len())` into
    /// `block` (indexed from `base`), then drop waveforms that can no longer contribute to
    /// this or any later block (the base only advances). Mirrors `run()`'s `place`.
    pub fn fill(&mut self, base: i64, block: &mut [Complex32]) {
        let end = base + block.len() as i64;
        for (wf, placed) in &mut self.pending {
            for (i, &s) in wf.samples.iter().enumerate() {
                let abs = wf.pos + i as i64;
                if abs >= base && abs < end {
                    block[(abs - base) as usize] = s;
                    *placed += 1;
                }
            }
        }
        // A waveform is spent once its last sample is before the next block's base.
        let audit = self.audit;
        let retired = &mut self.retired;
        self.pending.retain(|(wf, placed)| {
            let live = wf.pos + wf.samples.len() as i64 > end;
            if !live && audit {
                if *placed < wf.samples.len() {
                    // Retiring a waveform that was only partially served: the receiver saw a
                    // truncated burst (low SINR / CRC KO). Says how many samples made it.
                    eprintln!(
                        "[inj] PARTIAL serve {} pos={} len={} placed={}",
                        wf.tag,
                        wf.pos,
                        wf.samples.len(),
                        placed
                    );
                }
                retired.push((wf.pos, wf.samples.len(), wf.tag));
                if retired.len() > 16 {
                    retired.remove(0);
                }
            }
            live
        });
    }

    /// Number of waveforms that arrived after their injection window had already passed.
    pub fn deadline_misses(&self) -> u64 {
        self.misses
    }

    /// Waveforms still queued for future blocks (for queue-depth diagnostics).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wf(pos: i64, vals: &[f32]) -> ReadyWaveform {
        ReadyWaveform {
            pos,
            samples: vals.iter().map(|&v| Complex32::new(v, 0.0)).collect(),
            tag: "test",
        }
    }

    /// A waveform lands exactly at its absolute position, split across two blocks if it
    /// straddles a boundary, and is dropped once fully consumed.
    #[test]
    fn injection_places_across_blocks() {
        let mut t = InjectionTable::new();
        t.push(wf(6, &[1.0, 2.0, 3.0, 4.0]), 0); // positions 6..10
                                                 // Block [0,4): nothing overlaps.
        let mut b0 = vec![Complex32::new(0.0, 0.0); 4];
        t.fill(0, &mut b0);
        assert!(b0.iter().all(|c| c.re == 0.0));
        assert_eq!(t.pending_len(), 1); // still waiting
                                        // Block [4,8): positions 6,7 → block[2],block[3].
        let mut b1 = vec![Complex32::new(0.0, 0.0); 4];
        t.fill(4, &mut b1);
        assert_eq!(b1[2].re, 1.0);
        assert_eq!(b1[3].re, 2.0);
        assert_eq!(t.pending_len(), 1); // 8,9 still pending
                                        // Block [8,12): positions 8,9 → block[0],block[1]; then spent.
        let mut b2 = vec![Complex32::new(0.0, 0.0); 4];
        t.fill(8, &mut b2);
        assert_eq!(b2[0].re, 3.0);
        assert_eq!(b2[1].re, 4.0);
        assert_eq!(t.pending_len(), 0); // dropped
    }

    /// A waveform whose position is already behind the counter is a deadline miss.
    #[test]
    fn injection_counts_deadline_miss() {
        let mut t = InjectionTable::new();
        t.push(wf(100, &[1.0]), 50); // future → not a miss
        t.push(wf(10, &[1.0, 1.0]), 50); // 10..12 < 50 → miss
        assert_eq!(t.deadline_misses(), 1);
    }

    /// Two waveforms targeting the same block coexist (no clobber of unrelated samples).
    #[test]
    fn injection_multiple_waveforms() {
        let mut t = InjectionTable::new();
        t.push(wf(1, &[5.0]), 0);
        t.push(wf(3, &[7.0]), 0);
        let mut b = vec![Complex32::new(0.0, 0.0); 4];
        t.fill(0, &mut b);
        assert_eq!(b[1].re, 5.0);
        assert_eq!(b[3].re, 7.0);
        assert_eq!(b[0].re, 0.0);
        assert_eq!(b[2].re, 0.0);
    }
}
