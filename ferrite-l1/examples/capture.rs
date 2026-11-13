//! Capture downlink IQ from the ZMQ gNB to a file (interleaved f32 LE), serving
//! uplink zeros on the engine's UL thread meanwhile so the lockstep gNB keeps
//! producing.
//!
//!   cargo run -p ferrite-l1 --example capture -- <out.iq> <srate-MHz> <ms>

use ferrite_common::Iq;
use ferrite_l1::radio::{serve_uplink, UlPacing, UlServer, UlShared, ZmqUlSink};
use ferrite_l1::stream::BufferedStream;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = args.get(1).cloned().unwrap_or_else(|| "/tmp/capture.iq".into());
    let fs: f64 = args.get(2).and_then(|a| a.parse::<f64>().ok()).unwrap_or(15.36) * 1e6;
    let ms: usize = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(60);
    let block = 1920;
    let src = ferrite_radio::zmq::ZmqSource::connect("tcp://127.0.0.1:2100", fs, 5_000).expect("DL");
    let sink = ferrite_radio::zmq::ZmqSink::bind("tcp://127.0.0.1:2101", fs, block).expect("UL");
    let server = UlServer { sink: Box::new(ZmqUlSink(sink)), pacing: UlPacing::FreeRunning, tx_rx_offset: 0, block_len: block, start_index: 0 };
    let shared = UlShared::new(0);
    {
        let shared = shared.clone();
        std::thread::spawn(move || serve_uplink(server, shared, 1920, fs));
    }
    let mut dl = BufferedStream::spawn(src, block);
    let total = (fs * ms as f64 / 1000.0) as usize;
    let mut buf = vec![Iq::default(); total];
    dl.read_exact(&mut buf).expect("read");
    let mut file = std::fs::File::create(&out).expect("create");
    for s in &buf {
        file.write_all(&s.re.to_le_bytes()).unwrap();
        file.write_all(&s.im.to_le_bytes()).unwrap();
    }
    shared.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    eprintln!("captured {} samples to {out}", buf.len());
}
