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
        std::thread::spawn(move || {
            let mut buf = vec![Iq::default(); block];
            loop {
                match source.read(&mut buf) {
                    Ok(0) => break, // end of stream
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break; // consumer dropped
                        }
                    }
                    Err(_) => break,
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
