//! Type I single-panel PMI codebook arithmetic (TS 38.214 §5.2.2.2.1, TS
//! 38.212 Table 6.3.1.1.2-1): the panel shape `(N1, N2)` and oversampling
//! `(O1, O2)`, the PMI field widths per rank, the value ranges the codebook
//! is searched over, and the rank-2 beam offsets `(k1, k2)`. Codebook mode 1
//! only (the mode OCUDU configures). The precoding matrices themselves are
//! built in `ferrite-phy`.
//!
//! The widths match the field order the gNB unpacks: `i1,1 | i1,2 | i1,3 |
//! i2`, each field present only when its width is non-zero.

/// The CSI-RS port layout a PMI refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Codebook {
    /// No PMI (single port, or no `codebookConfig`).
    #[default]
    OnePort,
    /// Two ports (Table 5.2.2.2.1-1): `i2` only.
    TwoPort,
    /// `moreThanTwo`: `2·N1·N2` ports in a dual-polarised `N1 × N2` panel.
    SinglePanel { n1: u8, n2: u8 },
}

/// A Type I single-panel PMI. For two ports only `i2` is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Pmi {
    pub i11: u8,
    pub i12: u8,
    pub i13: u8,
    pub i2: u8,
}

/// Field widths (bits) of a PMI, in report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PmiSizes {
    pub i11: usize,
    pub i12: usize,
    pub i13: usize,
    pub i2: usize,
}

impl PmiSizes {
    pub fn total(&self) -> usize {
        self.i11 + self.i12 + self.i13 + self.i2
    }
}

/// Number of values each PMI field takes (the codebook search space).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmiRanges {
    pub i11: u8,
    pub i12: u8,
    pub i13: u8,
    pub i2: u8,
}

fn log2_ceil(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

impl Codebook {
    pub fn nof_ports(&self) -> u8 {
        match *self {
            Codebook::OnePort => 1,
            Codebook::TwoPort => 2,
            Codebook::SinglePanel { n1, n2 } => 2 * n1 * n2,
        }
    }

    /// `(N1, N2, O1, O2)`: O1 = 4 always, O2 = 4 for a 2-D panel, else 1
    /// (TS 38.214 Table 5.2.2.2.1-2).
    pub fn panel(&self) -> Option<(usize, usize, usize, usize)> {
        match *self {
            Codebook::SinglePanel { n1, n2 } => {
                let o2 = if n2 > 1 { 4 } else { 1 };
                Some((usize::from(n1), usize::from(n2), 4, o2))
            }
            _ => None,
        }
    }

    /// Width of the RI field for `allowed` ranks in the `ri-Restriction`
    /// (TS 38.212 Table 6.3.1.1.2-3: at most 1 bit for two ports, 2 for four).
    pub fn ri_bits(&self, allowed: usize) -> usize {
        let bits = log2_ceil(allowed);
        match self.nof_ports() {
            1 => 0,
            2 => bits.min(1),
            4 => bits.min(2),
            _ => bits,
        }
    }

    /// PMI field widths at `rank` (TS 38.212 Table 6.3.1.1.2-1, mode 1).
    /// Zero for combinations the codebook does not define.
    pub fn pmi_sizes(&self, rank: u8) -> PmiSizes {
        let zero = PmiSizes::default();
        let (n1, n2, o1, o2) = match *self {
            Codebook::OnePort => return zero,
            Codebook::TwoPort => {
                return PmiSizes {
                    i2: if rank >= 2 { 1 } else { 2 },
                    ..zero
                }
            }
            Codebook::SinglePanel { .. } => match self.panel() {
                Some(p) => p,
                None => return zero,
            },
        };
        let ports = 2 * n1 * n2;
        let i11 = log2_ceil(n1 * o1);
        let i12 = log2_ceil(n2 * o2);
        let (i13, i2) = match rank {
            1 => (0, 2),
            2 if ports == 4 && n2 == 1 => (1, 1),
            2 => (2, 1),
            3 | 4 if ports == 4 => (0, 1),
            3 | 4 if ports == 8 => (2, 1),
            _ => return zero,
        };
        PmiSizes { i11, i12, i13, i2 }
    }

    /// The values each field takes at `rank` (ranks 1 and 2; what a UE with
    /// at most two receive antennas searches). `None` otherwise.
    pub fn pmi_ranges(&self, rank: u8) -> Option<PmiRanges> {
        match *self {
            Codebook::OnePort => None,
            Codebook::TwoPort => Some(PmiRanges {
                i11: 1,
                i12: 1,
                i13: 1,
                i2: if rank >= 2 { 2 } else { 4 },
            }),
            Codebook::SinglePanel { .. } => {
                let (n1, n2, o1, o2) = self.panel()?;
                let (i11, i12) = ((n1 * o1) as u8, (n2 * o2) as u8);
                match rank {
                    1 => Some(PmiRanges {
                        i11,
                        i12,
                        i13: 1,
                        i2: 4,
                    }),
                    2 => Some(PmiRanges {
                        i11,
                        i12,
                        // Table 5.2.2.2.1-3: two offsets for N1 = 2, N2 = 1,
                        // four otherwise.
                        i13: if n1 == 2 && n2 == 1 { 2 } else { 4 },
                        i2: 2,
                    }),
                    _ => None,
                }
            }
        }
    }

    /// `(k1, k2)` of the second layer's beam at rank 2 (TS 38.214 Table
    /// 5.2.2.2.1-3).
    pub fn rank2_offsets(&self, i13: u8) -> (usize, usize) {
        let Some((n1, n2, o1, o2)) = self.panel() else {
            return (0, 0);
        };
        let i13 = usize::from(i13);
        if n2 == 1 {
            // N1 = 2: i1,3 ∈ {0, 1}; N1 > 2: {0, 1, 2, 3}, k1 = i1,3·O1.
            (i13 * o1, 0)
        } else if n1 == n2 {
            [(0, 0), (o1, 0), (0, o2), (o1, o2)][i13.min(3)]
        } else {
            // N1 > N2 > 1.
            [(0, 0), (o1, 0), (0, o2), (2 * o1, 0)][i13.min(3)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOUR: Codebook = Codebook::SinglePanel { n1: 2, n2: 1 };

    /// The widths OCUDU's `get_pmi_sizes_typeI_single_panel` gives (and
    /// therefore unpacks) for the configurations it builds.
    #[test]
    fn widths_match_the_gnb() {
        let s = |cb: Codebook, r| {
            let p = cb.pmi_sizes(r);
            (p.i11, p.i12, p.i13, p.i2)
        };
        assert_eq!(s(FOUR, 1), (3, 0, 0, 2));
        assert_eq!(s(FOUR, 2), (3, 0, 1, 1));
        assert_eq!(s(FOUR, 3), (3, 0, 0, 1));
        assert_eq!(s(FOUR, 4), (3, 0, 0, 1));
        let eight = Codebook::SinglePanel { n1: 4, n2: 1 };
        assert_eq!(s(eight, 1), (4, 0, 0, 2));
        assert_eq!(s(eight, 2), (4, 0, 2, 1));
        let two_two = Codebook::SinglePanel { n1: 2, n2: 2 };
        assert_eq!(s(two_two, 1), (3, 3, 0, 2));
        assert_eq!(s(Codebook::TwoPort, 1), (0, 0, 0, 2));
        assert_eq!(s(Codebook::TwoPort, 2), (0, 0, 0, 1));
        assert_eq!(FOUR.pmi_sizes(1).total(), 5);
        assert_eq!(FOUR.ri_bits(4), 2);
        assert_eq!(FOUR.ri_bits(2), 1);
        assert_eq!(Codebook::TwoPort.ri_bits(2), 1);
        assert_eq!(Codebook::OnePort.ri_bits(1), 0);
    }

    #[test]
    fn rank2_search_space() {
        let r = FOUR.pmi_ranges(2).unwrap();
        assert_eq!((r.i11, r.i12, r.i13, r.i2), (8, 1, 2, 2));
        assert_eq!(FOUR.rank2_offsets(1), (4, 0));
        // Every value of the search space fits its field.
        for rank in 1..=2 {
            let (s, r) = (FOUR.pmi_sizes(rank), FOUR.pmi_ranges(rank).unwrap());
            for (bits, n) in [(s.i11, r.i11), (s.i12, r.i12), (s.i13, r.i13), (s.i2, r.i2)] {
                assert!(
                    usize::from(n) <= 1 << bits,
                    "rank {rank}: {n} values in {bits} bits"
                );
            }
        }
    }
}
