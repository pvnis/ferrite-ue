//! Decoupled radio streaming: a dedicated thread drains a [`SampleSource`]
//! continuously (a stalled consumer must never stall the radio — a ZMQ gNB's
//! DU runs on wall-clock and error-spirals if its TX buffer backs up), while
//! the consumer reads at its own pace from an unbounded queue.

use ferrite_radio::SampleSource;
use ferrite_common::{Error, Iq, Result};
use std::sync::mpsc;

/// Consumer end of a continuously drained sample stream.
pub struct BufferedStream {
    rx: mpsc::Receiver<Vec<Iq>>,
    pending: Vec<Iq>,
    pos: usize,
    /// Total samples handed to the consumer since the stream started.
    consumed: usize,
}

impl BufferedStream {
    /// Spawn the drain thread over `source`, reading `block` samples per call.
    pub fn spawn<S: SampleSource + Send + 'static>(mut source: S, block: usize) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<Iq>>();
        let overrun_dbg = std::env::var_os("FERRITE_PERF").is_some();
        std::thread::spawn(move || {
            let mut buf = vec![Iq::default(); block];
            let mut errs = 0u32;
            let mut total_errs = 0u64;
            let mut total_ok = 0u64;
            loop {
                match source.read(&mut buf) {
                    Ok(0) => break, // end of stream (file source)
                    Ok(n) => {
                        errs = 0;
                        total_ok += n as u64;
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break; // consumer dropped
                        }
                    }
                    // Transient device error — an SDR RX overrun loses the samples that piled up
                    // but the stream continues, so DON'T kill the pipeline (a hard break here was
                    // the `dl stream ended` panic on the first overrun). Skip and retry; the lost
                    // samples are a timing discontinuity that continuous DL tracking re-aligns.
                    // Only a long run of consecutive errors (device gone) ends the stream.
                    Err(e) => {
                        errs += 1;
                        total_errs += 1;
                        if errs == 1 || errs % 500 == 0 {
                            log::warn!("radio read error ({errs} consecutive): {e}");
                        }
                        std::thread::sleep(std::time::Duration::from_micros(200));
                        if overrun_dbg && total_errs % 50 == 0 {
                            eprintln!("[sdr-rx] {total_errs} overruns / {total_ok} samples read");
                        }
                        if errs > 2000 {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            rx,
            pending: Vec::new(),
            pos: 0,
            consumed: 0,
        }
    }

    /// Absolute stream index of the next sample `read_exact` will return.
    pub fn position(&self) -> usize {
        self.consumed
    }

    /// Discard everything currently buffered (non-blocking), returning how many samples were
    /// flushed. Brings a consumer that fell behind during a slow startup (cell search) back to
    /// (near) real time — otherwise the huge backlog runs the timeline behind and its memory
    /// pressure stalls the drain thread into overruns. `consumed` still advances, so `position()`
    /// remains a true absolute sample count and downstream timing stays consistent.
    pub fn drain_backlog(&mut self) -> usize {
        let mut flushed = self.pending.len() - self.pos;
        self.pending.clear();
        self.pos = 0;
        while let Ok(chunk) = self.rx.try_recv() {
            flushed += chunk.len();
        }
        self.consumed += flushed;
        flushed
    }

    /// Read exactly `buf.len()` samples (blocking). Errors if the drain thread
    /// has stopped (source ended or failed).
    pub fn read_exact(&mut self, buf: &mut [Iq]) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.pos >= self.pending.len() {
                self.pending = self
                    .rx
                    .recv()
                    .map_err(|_| Error::Radio("stream ended".into()))?;
                self.pos = 0;
            }
            let take = (self.pending.len() - self.pos).min(buf.len() - filled);
            buf[filled..filled + take]
                .copy_from_slice(&self.pending[self.pos..self.pos + take]);
            self.pos += take;
            filled += take;
        }
        self.consumed += buf.len();
        Ok(())
    }

    /// Discard exactly `n` samples.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        let mut remaining = n;
        while remaining > 0 {
            if self.pos >= self.pending.len() {
                self.pending = self
                    .rx
                    .recv()
                    .map_err(|_| Error::Radio("stream ended".into()))?;
                self.pos = 0;
            }
            let take = (self.pending.len() - self.pos).min(remaining);
            self.pos += take;
            remaining -= take;
        }
        self.consumed += n;
        Ok(())
    }
}
