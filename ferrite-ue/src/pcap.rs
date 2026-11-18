//! Protocol capture for Wireshark: one pcap file of "exported PDUs" (link
//! type 252, `WIRESHARK_UPPER_PDU`), each packet naming the dissector that
//! decodes it, so the file opens in Wireshark with no preferences to set:
//!
//! * `mac-nr-framed`: MAC PDUs (DL transport blocks that passed the CRC, UL
//!   PUSCH transport blocks), with the MAC-NR context header (radio type,
//!   direction, RNTI type and value, UE id, HARQ process, SFN / subframe).
//! * `nr-rrc.*`: RRC messages as RRC sees them, i.e. after PDCP deciphering
//!   (DL / UL DCCH, DL / UL CCCH, BCCH-DL-SCH, PCCH).
//! * `nas-5gs`: NAS messages in plain text, before protection (UL) / after
//!   deciphering (DL). On the air both are ciphered; this is what lets
//!   Wireshark show them.
//!
//! The framing follows Wireshark's `packet-mac-nr.h` / `exported_pdu.h`,
//! byte-identical to the srsRAN / OCUDU MAC pcap writers. `mac-nr-framed`
//! needs Wireshark 4.4 or later; for older versions, [`Pcap::create`] with
//! `mac_udp` writes MAC PDUs as UDP datagrams starting `"mac-nr"` (OCUDU's
//! "udp" mode), decoded once the `mac_nr_udp` heuristic is enabled
//! (`tshark --enable-heuristic mac_nr_udp`). A write error
//! closes the capture (logged once); it never stops the UE.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// `LINKTYPE_WIRESHARK_UPPER_PDU`.
const DLT_EXPORTED_PDU: u32 = 252;
/// `EXP_PDU_TAG_DISSECTOR_NAME`.
const TAG_DISSECTOR_NAME: u16 = 12;

/// Start of a UDP-framed MAC-NR datagram.
const MAC_NR_START: &[u8] = b"mac-nr";

/// MAC-NR context (Wireshark `packet-mac-nr.h`).
mod mac_nr {
    pub const FDD_RADIO: u8 = 1;
    pub const TDD_RADIO: u8 = 2;
    pub const UPLINK: u8 = 0;
    pub const DOWNLINK: u8 = 1;
    pub const P_RNTI: u8 = 1;
    pub const RA_RNTI: u8 = 2;
    pub const C_RNTI: u8 = 3;
    pub const SI_RNTI: u8 = 4;
    pub const PAYLOAD_TAG: u8 = 0x01;
    pub const RNTI_TAG: u8 = 0x02;
    pub const UEID_TAG: u8 = 0x03;
    pub const FRAME_SUBFRAME_TAG: u8 = 0x04;
    pub const HARQID_TAG: u8 = 0x06;
}

/// Link direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Uplink,
    Downlink,
}

/// Which RNTI a MAC PDU was addressed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RntiType {
    P,
    Ra,
    /// C-RNTI and TC-RNTI (Wireshark has no separate type for the latter).
    C,
    Si,
}

/// A MAC PDU's context.
#[derive(Clone, Copy, Debug)]
pub struct MacContext {
    pub tdd: bool,
    pub dir: Dir,
    pub rnti_type: RntiType,
    pub rnti: u16,
    pub harq_id: u8,
    pub sfn: u16,
    /// Subframe within the frame (0..10).
    pub subframe: u8,
}

/// The NR RRC logical channel a message belongs to (its Wireshark dissector).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RrcChannel {
    DlDcch,
    UlDcch,
    DlCcch,
    UlCcch,
    BcchDlSch,
    Pcch,
}

impl RrcChannel {
    fn dissector(self) -> &'static str {
        match self {
            RrcChannel::DlDcch => "nr-rrc.dl.dcch",
            RrcChannel::UlDcch => "nr-rrc.ul.dcch",
            RrcChannel::DlCcch => "nr-rrc.dl.ccch",
            RrcChannel::UlCcch => "nr-rrc.ul.ccch",
            RrcChannel::BcchDlSch => "nr-rrc.bcch.dl.sch",
            RrcChannel::Pcch => "nr-rrc.pcch",
        }
    }
}

/// The MAC-NR context header (everything up to and including the payload tag).
pub fn mac_context_header(c: &MacContext) -> Vec<u8> {
    let rnti_type = match c.rnti_type {
        RntiType::P => mac_nr::P_RNTI,
        RntiType::Ra => mac_nr::RA_RNTI,
        RntiType::C => mac_nr::C_RNTI,
        RntiType::Si => mac_nr::SI_RNTI,
    };
    let mut h = vec![
        if c.tdd {
            mac_nr::TDD_RADIO
        } else {
            mac_nr::FDD_RADIO
        },
        match c.dir {
            Dir::Uplink => mac_nr::UPLINK,
            Dir::Downlink => mac_nr::DOWNLINK,
        },
        rnti_type,
        mac_nr::RNTI_TAG,
    ];
    h.extend_from_slice(&c.rnti.to_be_bytes());
    h.push(mac_nr::UEID_TAG);
    h.extend_from_slice(&1u16.to_be_bytes());
    h.extend_from_slice(&[mac_nr::HARQID_TAG, c.harq_id]);
    // SFN in the 12 MSBs, subframe in the 4 LSBs.
    h.push(mac_nr::FRAME_SUBFRAME_TAG);
    let fs = ((c.sfn & 0x3ff) << 4) | u16::from(c.subframe & 0x0f);
    h.extend_from_slice(&fs.to_be_bytes());
    h.push(mac_nr::PAYLOAD_TAG);
    h
}

/// The exported-PDU tags naming `dissector` (padded to 4 octets, then the
/// end-of-options tag).
pub fn exported_pdu_tags(dissector: &str) -> Vec<u8> {
    let name = dissector.as_bytes();
    let padded = name.len().div_ceil(4) * 4;
    let mut t = Vec::with_capacity(4 + padded + 4);
    t.extend_from_slice(&TAG_DISSECTOR_NAME.to_be_bytes());
    t.extend_from_slice(&(padded as u16).to_be_bytes());
    t.extend_from_slice(name);
    t.resize(4 + padded, 0);
    t.extend_from_slice(&[0, 0, 0, 0]);
    t
}

/// The capture file.
pub struct Pcap {
    out: Option<BufWriter<File>>,
    packets: u64,
    mac_udp: bool,
}

impl Pcap {
    /// Create `path` and write the pcap file header. `mac_udp`: MAC PDUs as
    /// UDP datagrams for Wireshark before 4.4 (see the module docs).
    pub fn create(path: &Path, mac_udp: bool) -> std::io::Result<Self> {
        let mut out = BufWriter::new(File::create(path)?);
        out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?; // timezone
        out.write_all(&0u32.to_le_bytes())?; // sigfigs
        out.write_all(&65_535u32.to_le_bytes())?; // snaplen
        out.write_all(&DLT_EXPORTED_PDU.to_le_bytes())?;
        Ok(Self {
            out: Some(out),
            packets: 0,
            mac_udp,
        })
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn mac(&mut self, c: &MacContext, pdu: &[u8]) {
        if pdu.is_empty() {
            return;
        }
        let header = mac_context_header(c);
        if self.mac_udp {
            let len = 8 + MAC_NR_START.len() + header.len() + pdu.len();
            let mut udp = Vec::with_capacity(8);
            udp.extend_from_slice(&0xbeefu16.to_be_bytes());
            udp.extend_from_slice(&0xdeadu16.to_be_bytes());
            udp.extend_from_slice(&(len as u16).to_be_bytes());
            udp.extend_from_slice(&[0, 0]);
            self.packet("udp", &[&udp, MAC_NR_START, &header, pdu]);
        } else {
            self.packet("mac-nr-framed", &[&header, pdu]);
        }
    }

    pub fn rrc(&mut self, ch: RrcChannel, pdu: &[u8]) {
        if !pdu.is_empty() {
            self.packet(ch.dissector(), &[pdu]);
        }
    }

    pub fn nas(&mut self, pdu: &[u8]) {
        if !pdu.is_empty() {
            self.packet("nas-5gs", &[pdu]);
        }
    }

    fn packet(&mut self, dissector: &str, parts: &[&[u8]]) {
        let Some(out) = self.out.as_mut() else {
            return;
        };
        let tags = exported_pdu_tags(dissector);
        let len = tags.len() + parts.iter().map(|p| p.len()).sum::<usize>();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut write = || -> std::io::Result<()> {
            out.write_all(&(now.as_secs() as u32).to_le_bytes())?;
            out.write_all(&now.subsec_micros().to_le_bytes())?;
            out.write_all(&(len as u32).to_le_bytes())?;
            out.write_all(&(len as u32).to_le_bytes())?;
            out.write_all(&tags)?;
            parts.iter().try_for_each(|p| out.write_all(p))
        };
        match write() {
            Ok(()) => self.packets += 1,
            Err(e) => {
                log::error!("pcap: write failed ({e}); capture stopped");
                self.out = None;
            }
        }
    }

    pub fn flush(&mut self) {
        if let Some(out) = self.out.as_mut() {
            if let Err(e) = out.flush() {
                log::error!("pcap: flush failed ({e}); capture stopped");
                self.out = None;
            }
        }
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context header OCUDU's `nr_pcap_pack_mac_context_to_buffer`
    /// writes for the same fields.
    #[test]
    fn mac_context_matches_the_wireshark_layout() {
        let h = mac_context_header(&MacContext {
            tdd: true,
            dir: Dir::Downlink,
            rnti_type: RntiType::C,
            rnti: 0x4601,
            harq_id: 3,
            sfn: 517,
            subframe: 7,
        });
        assert_eq!(
            h,
            [2, 1, 3, 0x02, 0x46, 0x01, 0x03, 0, 1, 0x06, 3, 0x04, 0x20, 0x57, 0x01]
        );
    }

    #[test]
    fn dissector_tag_is_padded_and_terminated() {
        let t = exported_pdu_tags("nas-5gs");
        assert_eq!(
            t,
            [0, 12, 0, 8, b'n', b'a', b's', b'-', b'5', b'g', b's', 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn file_layout() {
        let dir = std::env::temp_dir().join(format!("ferrite-pcap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("t.pcap");
        {
            let mut p = Pcap::create(&path, false).unwrap();
            p.nas(&[0x7e, 0x00, 0x41]);
            assert_eq!(p.packets(), 1);
        }
        let b = std::fs::read(&path).unwrap();
        assert_eq!(&b[..4], &0xa1b2_c3d4u32.to_le_bytes());
        assert_eq!(&b[20..24], &252u32.to_le_bytes());
        // Record header: incl_len = 16 tag octets + 3 payload octets.
        assert_eq!(&b[32..36], &19u32.to_le_bytes());
        assert_eq!(&b[b.len() - 3..], &[0x7e, 0x00, 0x41]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
