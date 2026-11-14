//! Shared fixtures: the live captures from the OCUDU n78 TDD 10 MHz cell
//! (PCI 1, 24-RB carrier at 30 kHz, CORESET#0 index 2) and the MIB facts
//! the UE had when it received them.
#![allow(dead_code)]

use ferrite_common::DuplexMode;
use ferrite_rrc::derive::{MibInfo, RadioInfo};

/// SIB1 (BCCH-DL-SCH) transport block: PLMN 001/01, TAC 7, band n78.
pub const SIB1_HEX: &str = "748101701040040200000e000a680018056109a008200042e02050900c316a61b3704020000080800041a2352412130426931860000042ee18b53224f8050664abff0124e9106e28dc61b8e372c6fbf56c70ea008580d003058b6822800000000000000000";
/// RRCSetup (DL-CCCH) with SRB1 and the dedicated CellGroupConfig.
pub const RRC_SETUP_HEX: &str = "20400408e2e00580088bd76380830f0003e0102341e0400020904c0ca8000f8000000000183708420001101650020c00000081a6040494280000e2400044d55921060004103081431308122858c1a387800004280004005a8000800428080c005a80810004281014005a8101800428181c005a81820028200900a09028028280b00a0b030028300d00a0d038028380f0ba084092c6050e1fa2b3c4de4d03a41078bbf03043800000071ffacc46a9aae502c0000432ec00000100000000000006115aa8a008e00200410400004200b8801c040821000008401708038101082000010802e10070302084000021005c300e080420800004200b860010000001043010203040382c00000e20000001002000403000404801100520000118800f38e000";

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub fn mib() -> MibInfo {
    let cs0 = ferrite_phy::coreset0::coreset0_config(30, 30, 10, 2).unwrap();
    MibInfo { pci: 1, mu: 1, dmrs_typea_pos: 2, k_ssb: 0, coreset0_index: 2, ss0_index: 0, ssb_index: 0, ssb_scs_khz: 30, ssb_arfcn: 626000, coreset0_n_rb: cs0.n_rb as u16, coreset0_n_symb: cs0.n_symb as u8, coreset0_offset_rb: cs0.offset_rb }
}

pub fn radio() -> RadioInfo {
    RadioInfo { fs: 15.36e6, duplex: DuplexMode::Tdd, band: 78 }
}

/// MSB-first bit packer for hand-built UPER messages.
pub struct Bits(pub Vec<u8>);

impl Bits {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn put(&mut self, v: u64, n: usize) -> &mut Self {
        for i in (0..n).rev() {
            self.0.push(((v >> i) & 1) as u8);
        }
        self
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.0.len().div_ceil(8)];
        for (i, b) in self.0.iter().enumerate() {
            out[i / 8] |= b << (7 - i % 8);
        }
        out
    }
}

impl Default for Bits {
    fn default() -> Self {
        Self::new()
    }
}
