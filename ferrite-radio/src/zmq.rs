//! ZMQ IQ transport, wire-compatible with the srsRAN/OCUDU `zmq` radio driver.
//!
//! Protocol (per direction):
//! * The **transmitter** binds a `REP` socket. It waits for a small request
//!   message, then replies with a block of interleaved `complex<f32>` samples
//!   (native little-endian, arbitrary block length).
//! * The **receiver** is a `REQ` client: send a 1-byte request, receive a block.
//!
//! For a UE against a gNB configured with
//! `device_args: tx_port=tcp://A:2000,rx_port=tcp://A:2001`:
//! * [`ZmqSource`] connects to `tcp://A:2000` and pulls downlink samples;
//! * [`ZmqSink`] binds `tcp://A:2001` and serves uplink samples to the gNB.

use ferrite_common::{Error, Iq, Result};
use num_complex::Complex32;

fn zerr(e: ::zmq::Error) -> Error {
    Error::Radio(format!("zmq: {e}"))
}

/// Downlink receiver: REQ client pulling sample blocks from a gNB's TX REP port.
pub struct ZmqSource {
    socket: ::zmq::Socket,
    _ctx: ::zmq::Context,
    sample_rate: f64,
    /// Leftover samples from the last block not yet consumed by `read`.
    pending: Vec<Iq>,
    pending_pos: usize,
}

impl ZmqSource {
    /// Connect to `endpoint` (e.g. `tcp://127.0.0.1:2000`).
    ///
    /// `recv_timeout_ms` bounds how long a `read` waits for the gNB to produce
    /// samples before returning an error.
    pub fn connect(endpoint: &str, sample_rate: f64, recv_timeout_ms: i32) -> Result<Self> {
        let ctx = ::zmq::Context::new();
        let socket = ctx.socket(::zmq::REQ).map_err(zerr)?;
        socket.set_rcvtimeo(recv_timeout_ms).map_err(zerr)?;
        socket.set_sndtimeo(recv_timeout_ms).map_err(zerr)?;
        socket.set_linger(0).map_err(zerr)?;
        // A REQ socket that timed out waiting for a reply may not send again
        // (EFSM); relaxed + correlate lets a read retry re-issue the request.
        socket.set_req_relaxed(true).map_err(zerr)?;
        socket.set_req_correlate(true).map_err(zerr)?;
        socket.connect(endpoint).map_err(zerr)?;
        Ok(Self {
            socket,
            _ctx: ctx,
            sample_rate,
            pending: Vec::new(),
            pending_pos: 0,
        })
    }

    /// Request one block of samples from the transmitter.
    fn fetch_block(&mut self) -> Result<()> {
        self.socket.send(&[0u8][..], 0).map_err(zerr)?;
        let msg = self.socket.recv_msg(0).map_err(zerr)?;
        let bytes: &[u8] = &msg;
        if !bytes.len().is_multiple_of(8) {
            return Err(Error::Radio(format!(
                "zmq: block of {} bytes is not a whole number of complex<f32>",
                bytes.len()
            )));
        }
        self.pending.clear();
        self.pending_pos = 0;
        self.pending.reserve(bytes.len() / 8);
        for &[r0, r1, r2, r3, i0, i1, i2, i3] in bytes.as_chunks::<8>().0 {
            let re = f32::from_le_bytes([r0, r1, r2, r3]);
            let im = f32::from_le_bytes([i0, i1, i2, i3]);
            self.pending.push(Complex32::new(re, im));
        }
        Ok(())
    }
}

impl crate::SampleSource for ZmqSource {
    fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    fn read(&mut self, buf: &mut [Iq]) -> Result<usize> {
        if self.pending_pos >= self.pending.len() {
            self.fetch_block()?;
        }
        let avail = &self.pending[self.pending_pos..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.pending_pos += n;
        Ok(n)
    }
}

/// Uplink transmitter: binds a REP socket and serves sample blocks to the gNB's
/// RX REQ client. Until the UE has a real uplink, [`ZmqSink::serve_zeros`] keeps
/// the gNB's receive chain (and therefore its clock) running.
pub struct ZmqSink {
    socket: ::zmq::Socket,
    _ctx: ::zmq::Context,
    sample_rate: f64,
    block_len: usize,
}

impl ZmqSink {
    /// Bind `endpoint` (e.g. `tcp://127.0.0.1:2001`); each request is answered
    /// with `block_len` samples.
    pub fn bind(endpoint: &str, sample_rate: f64, block_len: usize) -> Result<Self> {
        let ctx = ::zmq::Context::new();
        let socket = ctx.socket(::zmq::REP).map_err(zerr)?;
        socket.set_rcvtimeo(100).map_err(zerr)?;
        socket.set_linger(0).map_err(zerr)?;
        socket.bind(endpoint).map_err(zerr)?;
        Ok(Self {
            socket,
            _ctx: ctx,
            sample_rate,
            block_len,
        })
    }

    /// Nominal sample rate in samples/second.
    pub fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// Answer at most one pending request with zero samples. Returns `true` if a
    /// request was served. Call this in a loop (or a dedicated thread).
    pub fn serve_zeros(&mut self) -> Result<bool> {
        match self.socket.recv_msg(0) {
            Ok(_) => {
                let zeros = vec![0u8; self.block_len * 8];
                self.socket.send(&zeros[..], 0).map_err(zerr)?;
                Ok(true)
            }
            Err(::zmq::Error::EAGAIN) => Ok(false),
            Err(e) => Err(zerr(e)),
        }
    }

    /// Answer at most one pending request, filling the reply block via `fill`
    /// (passed the running uplink sample counter and a zero-initialised block).
    /// Advances the counter by the block length. Returns `true` if served.
    ///
    /// Because the gNB requests uplink and transmits downlink in lockstep, the
    /// counter tracks the gNB's receive sample index, letting the caller place a
    /// PRACH occasion at a downlink-derived sample position.
    pub fn serve_with(
        &mut self,
        counter: &mut u64,
        mut fill: impl FnMut(u64, &mut [Complex32]),
    ) -> Result<bool> {
        match self.socket.recv_msg(0) {
            Ok(_) => {
                let mut block = vec![Complex32::default(); self.block_len];
                fill(*counter, &mut block);
                let mut bytes = Vec::with_capacity(self.block_len * 8);
                for s in &block {
                    bytes.extend_from_slice(&s.re.to_le_bytes());
                    bytes.extend_from_slice(&s.im.to_le_bytes());
                }
                self.socket.send(&bytes[..], 0).map_err(zerr)?;
                *counter += self.block_len as u64;
                Ok(true)
            }
            Err(::zmq::Error::EAGAIN) => Ok(false),
            Err(e) => Err(zerr(e)),
        }
    }

    /// Uplink block length (samples per served request).
    pub fn block_len(&self) -> usize {
        self.block_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SampleSource;

    /// Loopback: a mock "gNB transmitter" REP socket serves two known blocks;
    /// ZmqSource must deliver the concatenated stream through `read_exact`.
    #[test]
    fn source_pulls_blocks_from_rep_server() {
        let endpoint = "tcp://127.0.0.1:29517";
        let ctx = ::zmq::Context::new();
        let rep = ctx.socket(::zmq::REP).unwrap();
        rep.bind(endpoint).unwrap();

        let server = std::thread::spawn(move || {
            for base in [0u32, 100] {
                let _req = rep.recv_msg(0).unwrap();
                let mut bytes = Vec::new();
                for i in 0..50u32 {
                    bytes.extend(((base + i) as f32).to_le_bytes());
                    bytes.extend((-((base + i) as f32)).to_le_bytes());
                }
                rep.send(&bytes[..], 0).unwrap();
            }
        });

        let mut src = ZmqSource::connect(endpoint, 15.36e6, 2_000).unwrap();
        let mut buf = vec![Complex32::default(); 100];
        assert!(src.read_exact(&mut buf).unwrap());
        for (i, s) in buf.iter().enumerate() {
            let expect = if i < 50 {
                i as f32
            } else {
                (i - 50 + 100) as f32
            };
            assert_eq!(s.re, expect);
            assert_eq!(s.im, -expect);
        }
        server.join().unwrap();
    }

    /// ZmqSink must answer a REQ client with the configured number of zeros.
    #[test]
    fn sink_serves_zeros() {
        let endpoint = "tcp://127.0.0.1:29518";
        let mut sink = ZmqSink::bind(endpoint, 15.36e6, 32).unwrap();

        let ctx = ::zmq::Context::new();
        let req = ctx.socket(::zmq::REQ).unwrap();
        req.set_rcvtimeo(2_000).unwrap();
        req.connect(endpoint).unwrap();
        req.send(&[0u8][..], 0).unwrap();

        // Serve until the request has been handled.
        while !sink.serve_zeros().unwrap() {}
        let msg = req.recv_msg(0).unwrap();
        assert_eq!(msg.len(), 32 * 8);
        assert!(msg.iter().all(|&b| b == 0));
    }
}
