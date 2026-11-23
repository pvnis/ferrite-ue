//! Producer side of the ISAC tap's shared-memory ring, the layout of
//! nextghq/morty `docs/shm_tap_ring.md` (layout version 1) that `isac-sensor
//! --shm` maps; ported from morty's `shm-tap` `RingWriter`.
//!
//! A 4096-byte control block, then `nof_slots` slots of `slot_size` bytes,
//! little-endian. Each slot is a 16-byte header (a seqlock word and the
//! record length) and one record. The producer writes every record into the
//! next slot, overwriting the oldest, and never waits: the slot's sequence
//! word is `2n + 1` while record `n` is written and `2n + 2` once it is
//! complete, so a reader that copied a slot while it was rewritten sees the
//! word change and drops the copy.

use memmap2::MmapRaw;
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{fence, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// "ISACRING" in file order.
const RING_MAGIC: u64 = u64::from_le_bytes(*b"ISACRING");
const LAYOUT_VERSION: u32 = 1;
const CONTROL_SIZE: usize = 4096;
const SLOT_HEADER_SIZE: usize = 16;
const SLOT_ALIGN: usize = 64;

/// Control block offsets.
mod offset {
    pub const MAGIC: usize = 0;
    pub const LAYOUT_VERSION: usize = 8;
    pub const CONTROL_SIZE: usize = 12;
    pub const SLOT_SIZE: usize = 16;
    pub const NOF_SLOTS: usize = 20;
    pub const RECORD_VERSION: usize = 24;
    pub const EPOCH: usize = 32;
    pub const WRITE_SEQ: usize = 64;
    pub const DROPPED: usize = 128;
    pub const OVERWRITTEN: usize = 136;
    pub const READ_SEQ: usize = 192;
}

/// Slot offsets.
mod slot {
    pub const SEQ: usize = 0;
    pub const LENGTH: usize = 8;
    pub const RECORD: usize = super::SLOT_HEADER_SIZE;
}

/// Path of a ring: a bare name lives in `/dev/shm`, anything with a slash is
/// a file path (as `isac-sensor --shm` resolves it).
pub fn ring_path(name: &str) -> PathBuf {
    if name.contains('/') {
        PathBuf::from(name)
    } else {
        PathBuf::from("/dev/shm").join(name)
    }
}

/// Slot size for records of up to `max_record_len` bytes.
pub fn slot_size_for(max_record_len: usize) -> usize {
    (SLOT_HEADER_SIZE + max_record_len).div_ceil(SLOT_ALIGN) * SLOT_ALIGN
}

/// The 8-byte word at `off` of the mapping, as an atomic.
///
/// # Safety
/// `base + off` must be inside a live mapping and 8-byte aligned. The mapping
/// is page-aligned and every offset passed is a multiple of 8.
unsafe fn atomic_at<'a>(base: *mut u8, off: usize) -> &'a AtomicU64 {
    &*(base.add(off) as *const AtomicU64)
}

/// The single producer of a ring.
pub struct RingWriter {
    map: MmapRaw,
    slot_size: usize,
    nof_slots: usize,
    next: u64,
}

impl RingWriter {
    /// Create the ring at `path`, replacing any previous one, with `nof_slots`
    /// slots (a power of two) of `slot_size` bytes (a multiple of 64).
    pub fn create(
        path: &Path,
        slot_size: usize,
        nof_slots: usize,
        record_version: u16,
    ) -> io::Result<Self> {
        if !nof_slots.is_power_of_two()
            || !slot_size.is_multiple_of(SLOT_ALIGN)
            || slot_size <= SLOT_HEADER_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nof_slots must be a power of two, slot_size a multiple of 64",
            ));
        }
        // A fresh file, so that a reader still mapping a previous producer's
        // ring keeps its pages and notices the replacement by the inode.
        let _ = std::fs::remove_file(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        file.set_len((CONTROL_SIZE + slot_size * nof_slots) as u64)?;
        let map = MmapRaw::map_raw(&file)?;
        let base = map.as_mut_ptr();
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
        // SAFETY: the mapping spans the control block; every offset is inside
        // it, and the magic's offset is 8-byte aligned in a page-aligned map.
        unsafe {
            let put32 = |o: usize, v: u32| base.add(o).cast::<u32>().write_unaligned(v.to_le());
            put32(offset::LAYOUT_VERSION, LAYOUT_VERSION);
            put32(offset::CONTROL_SIZE, CONTROL_SIZE as u32);
            put32(offset::SLOT_SIZE, slot_size as u32);
            put32(offset::NOF_SLOTS, nof_slots as u32);
            base.add(offset::RECORD_VERSION)
                .cast::<u16>()
                .write_unaligned(record_version.to_le());
            base.add(offset::EPOCH)
                .cast::<u64>()
                .write_unaligned(epoch.to_le());
            // The magic last: a reader takes the ring once it is there.
            atomic_at(base, offset::MAGIC).store(RING_MAGIC, Ordering::Release);
        }
        Ok(Self {
            map,
            slot_size,
            nof_slots,
            next: 0,
        })
    }

    /// Largest record a slot holds.
    pub fn max_record_len(&self) -> usize {
        self.slot_size - SLOT_HEADER_SIZE
    }

    /// Write one record without waiting. Returns `false`, counting it as
    /// dropped, when it does not fit in a slot.
    pub fn write(&mut self, record: &[u8]) -> bool {
        let base = self.map.as_mut_ptr();
        if record.len() > self.max_record_len() {
            self.count_dropped();
            return false;
        }
        let n = self.next;
        let nof_slots = self.nof_slots as u64;
        // SAFETY: the slot index is below nof_slots, so the slot and the
        // record (bounded by the slot size above) lie inside the mapping; the
        // atomics are at multiples of 8 from page-aligned or 64-byte-aligned
        // starts.
        unsafe {
            if n >= nof_slots
                && atomic_at(base, offset::READ_SEQ).load(Ordering::Relaxed) <= n - nof_slots
            {
                atomic_at(base, offset::OVERWRITTEN).fetch_add(1, Ordering::Relaxed);
            }
            let slot = base.add(CONTROL_SIZE + (n & (nof_slots - 1)) as usize * self.slot_size);
            let seq = atomic_at(slot, slot::SEQ);
            seq.store(2 * n + 1, Ordering::Relaxed);
            fence(Ordering::Release);
            slot.add(slot::LENGTH)
                .cast::<u32>()
                .write_unaligned((record.len() as u32).to_le());
            std::ptr::copy_nonoverlapping(record.as_ptr(), slot.add(slot::RECORD), record.len());
            seq.store(2 * n + 2, Ordering::Release);
            atomic_at(base, offset::WRITE_SEQ).store(n + 1, Ordering::Release);
        }
        self.next += 1;
        true
    }

    /// Count a record lost before the ring (the tap's own queue was full).
    pub fn count_dropped(&mut self) {
        // SAFETY: control block offset inside the mapping, 8-byte aligned.
        unsafe {
            atomic_at(self.map.as_mut_ptr(), offset::DROPPED).fetch_add(1, Ordering::Relaxed)
        };
    }

    /// Records written so far.
    pub fn written(&self) -> u64 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }

    fn u64_at(b: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    }

    /// The bytes a reader maps, checked against morty's layout.
    #[test]
    fn ring_has_morty_layout() {
        let dir = std::env::temp_dir().join(format!("ferrite_ring_{}", std::process::id()));
        let mut w = RingWriter::create(&dir, slot_size_for(100), 4, 4).unwrap();
        assert_eq!(slot_size_for(100), 128);
        for i in 0..6u8 {
            assert!(w.write(&[i; 100]));
        }
        assert!(
            !w.write(&[0; 113]),
            "a record larger than a slot is dropped"
        );
        let b = std::fs::read(&dir).unwrap();
        let _ = std::fs::remove_file(&dir);
        assert_eq!(b.len(), 4096 + 4 * 128);
        assert_eq!(&b[0..8], b"ISACRING");
        assert_eq!(
            (
                u32_at(&b, 8),
                u32_at(&b, 12),
                u32_at(&b, 16),
                u32_at(&b, 20)
            ),
            (1, 4096, 128, 4)
        );
        assert_eq!(u16::from_le_bytes([b[24], b[25]]), 4);
        // Six records written, one dropped, two overwritten unread (no reader).
        assert_eq!(
            (u64_at(&b, 64), u64_at(&b, 128), u64_at(&b, 136)),
            (6, 1, 2)
        );
        // Record 5 is in slot 1, committed, with its length and bytes.
        let s = 4096 + 128;
        assert_eq!((u64_at(&b, s), u32_at(&b, s + 8)), (2 * 5 + 2, 100));
        assert!(b[s + 16..s + 116].iter().all(|&x| x == 5));
    }

    #[test]
    fn rejects_bad_geometry() {
        let p = std::env::temp_dir().join("ferrite_ring_bad");
        assert!(RingWriter::create(&p, 100, 4, 4).is_err());
        assert!(RingWriter::create(&p, 128, 3, 4).is_err());
    }
}
