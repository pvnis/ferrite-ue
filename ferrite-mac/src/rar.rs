//! Random Access Response (TS 38.321 §6.1.5, §6.2.2, §6.2.3) and the RAR UL
//! grant (TS 38.213 §8.2).

/// One MAC RAR (§6.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar {
    pub rapid: u8,
    /// 12-bit timing advance command.
    pub ta: u16,
    /// 27-bit UL grant fields (TS 38.213 Table 8.2-1).
    pub grant: RarUlGrant,
    pub tc_rnti: u16,
}

pub use ferrite_fapi::RarUlGrant;

/// Result of parsing a RAR MAC PDU for a given RAPID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RarPdu {
    /// Backoff indicator in ms (from the BI subheader), if present.
    pub backoff_ms: Option<u16>,
    pub rars: Vec<Rar>,
}

/// Backoff parameter values (TS 38.321 Table 7.2-1), ms.
const BACKOFF_MS: [u16; 16] = [
    0, 10, 20, 30, 40, 60, 80, 120, 160, 240, 320, 480, 960, 1920, 1920, 1920,
];

/// Parse a RAR MAC PDU (one or more E/T/RAPID or E/T/R/R/BI subheaders, then the
/// 7-octet MAC RARs in order).
pub fn parse_rar_pdu(pdu: &[u8]) -> Option<RarPdu> {
    let mut i = 0usize;
    let mut rapids = Vec::new();
    let mut backoff_ms = None;
    loop {
        let sub = *pdu.get(i)?;
        i += 1;
        let e = (sub >> 7) & 1;
        let t = (sub >> 6) & 1;
        if t == 0 {
            backoff_ms = Some(BACKOFF_MS[(sub & 0x0f) as usize]);
        } else {
            rapids.push(sub & 0x3f);
        }
        if e == 0 {
            break;
        }
    }
    let mut rars = Vec::with_capacity(rapids.len());
    for rapid in rapids {
        let p = pdu.get(i..i + 7)?;
        i += 7;
        let ta = (((p[0] & 0x7f) as u16) << 5) | (p[1] >> 3) as u16;
        let g = (((p[1] & 0x07) as u32) << 24)
            | ((p[2] as u32) << 16)
            | ((p[3] as u32) << 8)
            | p[4] as u32;
        let grant = RarUlGrant {
            freq_hopping: (g >> 26) & 1 == 1,
            fdra: ((g >> 12) & 0x3fff) as u16,
            time_resource: ((g >> 8) & 0xf) as u8,
            mcs: ((g >> 4) & 0xf) as u8,
            tpc: ((g >> 1) & 0x7) as u8,
            csi_request: g & 1 == 1,
        };
        let tc_rnti = ((p[5] as u16) << 8) | p[6] as u16;
        rars.push(Rar {
            rapid,
            ta,
            grant,
            tc_rnti,
        });
    }
    Some(RarPdu { backoff_ms, rars })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_style_rar() {
        // E=0,T=1,RAPID=0 | TA=5 (0x000 0101 → bytes 0x00, 0x28 | grant MSB bits) ...
        // Build: TA=5, grant = hop 0, fdra 0x0123, time 0, mcs 0, tpc 7, csi 0; tc=0x4601.
        let ta: u16 = 5;
        let g: u32 = (0x0123u32 << 12) | (7 << 1);
        let mut pdu = vec![0x40u8];
        pdu.push(((ta >> 5) & 0x7f) as u8);
        pdu.push((((ta & 0x1f) as u8) << 3) | ((g >> 24) & 7) as u8);
        pdu.push((g >> 16) as u8);
        pdu.push((g >> 8) as u8);
        pdu.push(g as u8);
        pdu.extend_from_slice(&0x4601u16.to_be_bytes());
        let r = parse_rar_pdu(&pdu).unwrap();
        assert_eq!(r.backoff_ms, None);
        assert_eq!(r.rars.len(), 1);
        let rar = r.rars[0];
        assert_eq!(rar.rapid, 0);
        assert_eq!(rar.ta, 5);
        assert_eq!(rar.grant.fdra, 0x0123);
        assert_eq!(rar.grant.tpc, 7);
        assert_eq!(rar.tc_rnti, 0x4601);
    }

    #[test]
    fn backoff_then_rar() {
        let mut pdu = vec![0x80 | 0x03]; // E=1, T=0, BI=3 → 30 ms
        pdu.push(0x40 | 7); // E=0, T=1, RAPID 7
        pdu.extend_from_slice(&[0; 7]);
        let r = parse_rar_pdu(&pdu).unwrap();
        assert_eq!(r.backoff_ms, Some(30));
        assert_eq!(r.rars[0].rapid, 7);
    }
}
