//! Resource-allocation type 1 RIV coding (TS 38.214 §5.1.2.2.2 / §6.1.2.2.2).


/// Decode a resource-allocation-type-1 RIV over a BWP of `n_bwp` RBs
/// (38.214 §5.1.2.2.2 / §6.1.2.2.2) into `(rb_start, n_rb)`:
/// `RIV = N(L−1) + S` if `L−1 ≤ ⌊N/2⌋`, else `N(N−L+1) + (N−1−S)`.
/// `None` when the RIV does not describe a valid allocation.
pub fn riv_decode(riv: u32, n_bwp: usize) -> Option<(usize, usize)> {
    if n_bwp == 0 || riv as usize >= n_bwp * (n_bwp + 1) / 2 {
        return None;
    }
    let riv = riv as usize;
    let mut l = riv / n_bwp + 1;
    let mut s = riv % n_bwp;
    if l + s > n_bwp {
        l = n_bwp - l + 2;
        s = n_bwp - 1 - s;
    }
    (l >= 1 && s + l <= n_bwp).then_some((s, l))
}

/// Encode `(rb_start, n_rb)` to a type-1 RIV over `n_bwp` RBs.
pub fn riv_encode(rb_start: usize, n_rb: usize, n_bwp: usize) -> u32 {
    let (s, l, n) = (rb_start, n_rb, n_bwp);
    (if l - 1 <= n / 2 { n * (l - 1) + s } else { n * (n - l + 1) + (n - 1 - s) }) as u32
}

/// RIV of a DCI 1_0 received in a **common search space** (38.214 §5.1.2.2.2):
/// `N_BWP` is the CORESET#0 size and RB numbering starts at the lowest RB of
/// CORESET#0, which may sit above the BWP's lowest RB. Returns the allocation
/// as `(crb_start, n_rb)` in the numbering of `coreset0_first_crb`.
pub fn riv_decode_css(riv: u32, coreset0_rb: usize, coreset0_first_crb: usize) -> Option<(usize, usize)> {
    riv_decode(riv, coreset0_rb).map(|(s, l)| (coreset0_first_crb + s, l))
}

/// Decode a SLIV (`startSymbolAndLength`, 38.214 §5.1.2.1) into `(S, L)`.
pub fn sliv_decode(sliv: u8) -> Option<(usize, usize)> {
    let sliv = usize::from(sliv);
    if sliv >= 14 * 15 / 2 {
        return None;
    }
    let (mut l, mut s) = (sliv / 14 + 1, sliv % 14);
    if l + s > 14 {
        l = 14 - l + 2;
        s = 13 - s;
    }
    (l >= 1 && s + l <= 14).then_some((s, l))
}

