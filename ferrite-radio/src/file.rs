//! File-backed IQ source/sink using interleaved little-endian `f32` samples
//! (the common "cfile" / GNU Radio complex format: `re, im, re, im, …`).

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use ferrite_common::{Iq, Result};
use num_complex::Complex32;

use crate::{SampleSink, SampleSource};

/// Reads interleaved `f32` IQ samples from a file.
pub struct FileSource {
    reader: BufReader<File>,
    sample_rate: f64,
}

impl FileSource {
    /// Open `path`, tagging the stream with `sample_rate` (Hz).
    pub fn open(path: impl AsRef<Path>, sample_rate: f64) -> Result<Self> {
        Ok(Self {
            reader: BufReader::new(File::open(path)?),
            sample_rate,
        })
    }
}

impl SampleSource for FileSource {
    fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
        let mut bytes = [0u8; 8];
        for (i, slot) in buf.iter_mut().enumerate() {
            match self.reader.read_exact(&mut bytes) {
                Ok(()) => {
                    let [r0, r1, r2, r3, i0, i1, i2, i3] = bytes;
                    let re = f32::from_le_bytes([r0, r1, r2, r3]);
                    let im = f32::from_le_bytes([i0, i1, i2, i3]);
                    *slot = Complex32::new(re, im);
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(i);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(buf.len())
    }
}

/// Writes interleaved `f32` IQ samples to a file.
pub struct FileSink {
    writer: BufWriter<File>,
    sample_rate: f64,
}

impl FileSink {
    /// Create/truncate `path`, tagging the stream with `sample_rate` (Hz).
    pub fn create(path: impl AsRef<Path>, sample_rate: f64) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::new(File::create(path)?),
            sample_rate,
        })
    }
}

impl SampleSink for FileSink {
    fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    fn write(&mut self, buf: &[Iq]) -> Result<usize> {
        for s in buf {
            self.writer.write_all(&s.re.to_le_bytes())?;
            self.writer.write_all(&s.im.to_le_bytes())?;
        }
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_through_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("ferrite_iq_roundtrip.cfile");
        let samples: Vec<Iq> = (0..1000)
            .map(|n| Complex32::new(n as f32, -(n as f32)))
            .collect();

        let mut sink = FileSink::create(&path, 30.72e6).unwrap();
        assert_eq!(sink.write(&samples).unwrap(), samples.len());
        drop(sink);

        let mut src = FileSource::open(&path, 30.72e6).unwrap();
        assert_eq!(src.sample_rate(), 30.72e6);
        let mut buf = vec![Complex32::default(); samples.len()];
        assert!(src.read_exact(&mut buf).unwrap());
        assert_eq!(buf, samples);

        // Stream is exhausted now.
        let mut extra = [Complex32::default(); 4];
        assert_eq!(src.read(&mut extra).unwrap(), 0);

        std::fs::remove_file(&path).ok();
    }
}
