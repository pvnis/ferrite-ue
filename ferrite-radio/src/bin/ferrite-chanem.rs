//! `ferrite-chanem` — a baseband channel emulator spliced into the ZMQ IQ
//! transport between a gNB (srsRAN / OCUDU REQ-REP protocol) and a UE.
//!
//! ```text
//!   gNB tx REP ◀─REQ─ [DL: channel] ─REP▶ UE rx REQ      (one per DL antenna)
//!   gNB rx REQ ─REP▶ [UL: channel] ◀─REQ─ UE tx REP
//! ```
//!
//! Each request from a downstream side is answered with the processed
//! samples of one upstream block, so the lockstep pacing of the transport is
//! kept. The channel (see `ferrite_radio::channel`) models multipath fading
//! (TS 38.901 TDL-A/B/C, TS 36.101 EPA/EVA/ETU), a propagation delay, a UE
//! clock error (`--ppm`: the UE's LO and sample clock both off by ε, so the
//! downlink arrives −ε·f_DL off and stretched by 1+ε, the uplink +ε·f_UL off
//! and compressed), and white noise.
//!
//! ```text
//! ferrite-chanem --dl-up tcp://127.0.0.1:2100 --dl-bind tcp://127.0.0.1:2200 \
//!     --ul-up tcp://127.0.0.1:2201 --ul-bind tcp://127.0.0.1:2101 \
//!     --srate 15.36 --dl-freq-mhz 3390 --ul-freq-mhz 3390 \
//!     --model tdlc --ds-ns 300 --doppler-hz 5 --ppm 1 --delay-ns 500 --dl-snr-db 25 --ul-snr-db 25
//! ferrite-chanem --bench 2 --model tdlc --ds-ns 300 --antennas 2 --srate 15.36
//! ```

use ferrite_radio::channel::{profile, Link, LinkConfig};
use num_complex::Complex32;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

const USAGE: &str =
    "usage: ferrite-chanem --dl-up EP[,EP] --dl-bind EP[,EP] --ul-up EP --ul-bind EP --srate MHZ
  [--dl-freq-mhz F --ul-freq-mhz F] [--model none|tdla|tdlb|tdlc|epa|eva|etu] [--ds-ns NS]
  [--doppler-hz HZ] [--delay-ns NS] [--ppm PPM] [--dl-snr-db DB] [--ul-snr-db DB] [--seed N]
  [--bench SECONDS [--antennas N]]";

#[derive(Debug, Default)]
struct Args {
    dl_up: Vec<String>,
    dl_bind: Vec<String>,
    ul_up: Vec<String>,
    ul_bind: Vec<String>,
    srate_hz: f64,
    dl_freq_hz: f64,
    ul_freq_hz: f64,
    model: Option<String>,
    ds_s: f64,
    doppler_hz: f64,
    delay_s: f64,
    ppm: f64,
    dl_snr_db: Option<f64>,
    ul_snr_db: Option<f64>,
    seed: u64,
    bench_s: Option<f64>,
    antennas: usize,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        ds_s: 100e-9,
        seed: 1,
        antennas: 1,
        ..Args::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "-h" || flag == "--help" {
            return Err(USAGE.into());
        }
        let val = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        let num = |v: &str| v.parse::<f64>().map_err(|e| format!("{flag} {v}: {e}"));
        let list = |v: &str| v.split(',').map(str::to_string).collect::<Vec<_>>();
        match flag.as_str() {
            "--dl-up" => a.dl_up = list(&val),
            "--dl-bind" => a.dl_bind = list(&val),
            "--ul-up" => a.ul_up = list(&val),
            "--ul-bind" => a.ul_bind = list(&val),
            "--srate" => a.srate_hz = num(&val)? * 1e6,
            "--dl-freq-mhz" => a.dl_freq_hz = num(&val)? * 1e6,
            "--ul-freq-mhz" => a.ul_freq_hz = num(&val)? * 1e6,
            "--model" => a.model = (val != "none").then_some(val),
            "--ds-ns" => a.ds_s = num(&val)? * 1e-9,
            "--doppler-hz" => a.doppler_hz = num(&val)?,
            "--delay-ns" => a.delay_s = num(&val)? * 1e-9,
            "--ppm" => a.ppm = num(&val)?,
            "--dl-snr-db" => a.dl_snr_db = Some(num(&val)?),
            "--ul-snr-db" => a.ul_snr_db = Some(num(&val)?),
            "--seed" => a.seed = val.parse().map_err(|e| format!("--seed {val}: {e}"))?,
            "--bench" => a.bench_s = Some(num(&val)?),
            "--antennas" => {
                a.antennas = val.parse().map_err(|e| format!("--antennas {val}: {e}"))?
            }
            _ => return Err(format!("unknown option {flag}\n{USAGE}")),
        }
    }
    if a.srate_hz <= 0.0 {
        return Err(format!("--srate is required\n{USAGE}"));
    }
    if a.ppm != 0.0 && (a.dl_freq_hz <= 0.0 || a.ul_freq_hz <= 0.0) {
        return Err("--ppm needs --dl-freq-mhz and --ul-freq-mhz".into());
    }
    Ok(a)
}

/// The two directions' channel configurations.
fn links(a: &Args, n_dl: usize) -> Result<(LinkConfig, LinkConfig), String> {
    let taps = match &a.model {
        None => Vec::new(),
        Some(m) => profile(m)
            .ok_or_else(|| format!("unknown model {m}"))?
            .taps_s(a.ds_s),
    };
    let eps = a.ppm * 1e-6;
    let base = LinkConfig {
        taps,
        doppler_hz: a.doppler_hz,
        delay_s: a.delay_s,
        ..LinkConfig::ideal(a.srate_hz)
    };
    let dl = LinkConfig {
        n_in: n_dl,
        n_out: n_dl,
        // The UE samples at fs·(1+ε): each UE sample advances 1/(1+ε) gNB samples.
        rate: 1.0 / (1.0 + eps),
        cfo_hz: -eps * a.dl_freq_hz,
        snr_db: a.dl_snr_db,
        seed: a.seed,
        ..base.clone()
    };
    let ul = LinkConfig {
        rate: 1.0 + eps,
        cfo_hz: eps * a.ul_freq_hz,
        snr_db: a.ul_snr_db,
        seed: a.seed.wrapping_add(0x5EED),
        ..base
    };
    Ok((dl, ul))
}

fn to_samples(bytes: &[u8]) -> Vec<Complex32> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|&[r0, r1, r2, r3, i0, i1, i2, i3]| {
            Complex32::new(
                f32::from_le_bytes([r0, r1, r2, r3]),
                f32::from_le_bytes([i0, i1, i2, i3]),
            )
        })
        .collect()
}

fn to_bytes(samples: &[Complex32]) -> Vec<u8> {
    samples
        .iter()
        .flat_map(|s| s.re.to_le_bytes().into_iter().chain(s.im.to_le_bytes()))
        .collect()
}

fn zerr(what: &str) -> impl Fn(zmq::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

/// One processed block of one port.
type Block = Vec<Complex32>;

/// Blocks processed ahead of the downstream requests (on the output port
/// that has been read furthest).
const PIPELINE: usize = 6;

/// Queued blocks per output port, shared by the fetcher and the server.
///
/// The fetcher runs ahead only while the *least* full queue is below
/// [`PIPELINE`]; the other queues may grow. A multi-antenna reader need not
/// drain its ports evenly (the UE reads one port in large chunks, e.g. when
/// dropping its cell-search backlog, before the next), and a per-port bound
/// would then deadlock: the fetcher blocked on a full queue that the reader
/// will not touch until another, empty, queue delivers.
struct Depth {
    name: &'static str,
    queued: Mutex<Vec<usize>>,
    changed: Condvar,
}

impl Depth {
    fn new(name: &'static str, ports: usize) -> Self {
        Self {
            name,
            queued: Mutex::new(vec![0; ports]),
            changed: Condvar::new(),
        }
    }

    /// Wait until some queue is below [`PIPELINE`], then count one more block
    /// on every port.
    fn push(&self) -> Result<(), String> {
        fn poisoned<T>(_: T) -> String {
            "queue lock poisoned".to_string()
        }
        let mut q = self.queued.lock().map_err(poisoned)?;
        while q.iter().all(|&d| d >= PIPELINE) {
            let (g, t) = self
                .changed
                .wait_timeout(q, std::time::Duration::from_secs(2))
                .map_err(poisoned)?;
            q = g;
            if t.timed_out() {
                eprintln!("{}: downstream idle for 2 s, queues {:?}", self.name, *q);
            }
        }
        q.iter_mut().for_each(|d| *d += 1);
        Ok(())
    }

    /// Count one block taken off port `a`.
    fn pop(&self, a: usize) -> Result<(), String> {
        let mut q = self
            .queued
            .lock()
            .map_err(|_| "queue lock poisoned".to_string())?;
        if let Some(d) = q.get_mut(a) {
            *d = d.saturating_sub(1);
        }
        self.changed.notify_all();
        Ok(())
    }
}

/// Couples the two directions: uplink samples are delivered to the gNB at
/// most [`Coupling::margin`] ahead of the downlink samples taken from it.
///
/// A ZMQ gNB (OCUDU) consumes uplink only while it can transmit, and polls
/// both directions from one I/O thread. If the uplink gets ahead by more
/// than its receive buffer (614 400 samples) — e.g. the UE keeps answering
/// uplink requests while it is not reading downlink — that thread blocks
/// pushing uplink, the transmit side is never drained, and the gNB
/// deadlocks. A direct UE↔gNB link cannot get that far ahead; the emulator's
/// queues can.
struct Coupling {
    /// Downlink samples received from the gNB (first antenna).
    dl_in: AtomicU64,
    /// Uplink samples delivered to the gNB.
    ul_out: AtomicU64,
    margin: u64,
}

impl Coupling {
    /// Wait until `len` more uplink samples stay within the margin.
    fn admit_ul(&self, len: usize) {
        let len = len as u64;
        let since = Instant::now();
        let mut warned = 0;
        while self.ul_out.load(Relaxed) + len > self.dl_in.load(Relaxed) + self.margin {
            std::thread::sleep(std::time::Duration::from_micros(50));
            let s = since.elapsed().as_secs();
            if s >= 2 * (warned + 1) {
                warned += 1;
                eprintln!(
                    "UL: held {s} s: {} uplink samples delivered, {} downlink received",
                    self.ul_out.load(Relaxed),
                    self.dl_in.load(Relaxed)
                );
            }
        }
        self.ul_out.fetch_add(len, Relaxed);
    }
}

/// Which direction a [`serve`] call carries (for the [`Coupling`]).
#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Dl,
    Ul,
}

/// Serve one direction until an error: a fetcher thread pulls upstream
/// blocks, runs them through the channel and queues the outputs (see
/// [`Depth`] for how far ahead); a server thread per downstream port answers each request with
/// its next queued block. Pulling ahead takes the upstream round trip and the
/// processing off the downstream side's critical path; the transport aligns
/// by sample count, so the extra wall-clock latency does not move any timing.
fn serve(
    name: &'static str,
    dir: Dir,
    coupling: &Arc<Coupling>,
    ctx: &zmq::Context,
    up: &[String],
    bind: &[String],
    link: Link,
) -> Result<(), String> {
    let ups = up
        .iter()
        .map(|ep| {
            let s = ctx.socket(zmq::REQ).map_err(zerr("socket"))?;
            s.set_rcvtimeo(2_000).map_err(zerr("rcvtimeo"))?;
            s.set_linger(0).map_err(zerr("linger"))?;
            // Re-send after a timeout (the far side may not be up yet).
            s.set_req_relaxed(true).map_err(zerr("relaxed"))?;
            s.set_req_correlate(true).map_err(zerr("correlate"))?;
            s.connect(ep)
                .map_err(|e| format!("{name}: connect {ep}: {e}"))?;
            Ok(s)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let downs = bind
        .iter()
        .map(|ep| {
            let s = ctx.socket(zmq::REP).map_err(zerr("socket"))?;
            s.set_linger(0).map_err(zerr("linger"))?;
            s.bind(ep).map_err(|e| format!("{name}: bind {ep}: {e}"))?;
            Ok(s)
        })
        .collect::<Result<Vec<_>, String>>()?;
    eprintln!("{name}: {up:?} → {bind:?}");
    let (txs, rxs): (Vec<Sender<Block>>, Vec<Receiver<Block>>) =
        (0..downs.len()).map(|_| std::sync::mpsc::channel()).unzip();
    let depth = Arc::new(Depth::new(name, downs.len()));
    let fetch_depth = Arc::clone(&depth);
    let fetch_coupling = (dir == Dir::Dl).then(|| Arc::clone(coupling));
    std::thread::Builder::new()
        .name(format!("chanem-{name}-fetch"))
        .spawn(move || {
            let counted = fetch_coupling.as_deref();
            if let Err(e) = fetch_loop(name, &ups, link, &txs, &fetch_depth, counted) {
                eprintln!("{name}: fetcher stopped: {e}");
            }
        })
        .map_err(|e| format!("thread: {e}"))?;
    // One server per downstream port: a reader may block on one port until
    // another delivers, so one port's empty queue must never hold up the
    // replies of another.
    let (err_tx, err_rx) = std::sync::mpsc::channel::<String>();
    for (a, (down, rx)) in downs.into_iter().zip(rxs).enumerate() {
        let depth = Arc::clone(&depth);
        let err_tx = err_tx.clone();
        let gate = (dir == Dir::Ul).then(|| Arc::clone(coupling));
        std::thread::Builder::new()
            .name(format!("chanem-{name}-{a}"))
            .spawn(move || {
                let e = serve_port(&down, &rx, &depth, a, gate.as_deref())
                    .err()
                    .unwrap_or_default();
                let _ = err_tx.send(format!("{name} port {a}: {e}"));
            })
            .map_err(|e| format!("thread: {e}"))?;
    }
    drop(err_tx);
    Err(err_rx
        .recv()
        .unwrap_or_else(|_| format!("{name}: servers gone")))
}

/// Answer each request on `down` with the next block queued for port `a`
/// (uplink: once the [`Coupling`] admits it).
fn serve_port(
    down: &zmq::Socket,
    rx: &Receiver<Block>,
    depth: &Depth,
    a: usize,
    gate: Option<&Coupling>,
) -> Result<(), String> {
    loop {
        down.recv_msg(0).map_err(zerr("request"))?;
        let block = rx.recv().map_err(|_| "fetcher gone".to_string())?;
        depth.pop(a)?;
        if let Some(g) = gate {
            g.admit_ul(block.len());
        }
        down.send(to_bytes(&block), 0).map_err(zerr("reply"))?;
    }
}

/// Pull, process and queue upstream blocks until a send fails.
fn fetch_loop(
    name: &str,
    ups: &[zmq::Socket],
    mut link: Link,
    txs: &[Sender<Block>],
    depth: &Depth,
    counted: Option<&Coupling>,
) -> Result<(), String> {
    let mut report = Instant::now();
    let mut last_in = 0i64;
    // Wall time waiting for upstream replies, processing, waiting for queue
    // space (downstream slower), and blocks fetched, since the last report.
    let (mut t_up, mut t_proc, mut t_down, mut n_blocks) = (0f64, 0f64, 0f64, 0u64);
    // Samples received but not yet processed, per upstream port. A ZMQ
    // transmitter replies with whatever it has buffered for that port, so the
    // ports' reply lengths can differ; only their common length is processed
    // and the rest carried over, which keeps the antennas sample-aligned.
    // Every port is requested every round (as a direct reader would): a
    // transmitter produces all its ports together, so skipping the port that
    // is ahead can leave it blocked on that port's full buffer while we wait
    // for another.
    let mut pending: Vec<Vec<Complex32>> = vec![Vec::new(); ups.len()];
    loop {
        let t0 = Instant::now();
        for (p, (u, buf)) in ups.iter().zip(pending.iter_mut()).enumerate() {
            loop {
                u.send(&[0u8][..], 0).map_err(zerr("upstream request"))?;
                match u.recv_bytes(0) {
                    Ok(b) => {
                        let samples = to_samples(&b);
                        if let (0, Some(c)) = (p, counted) {
                            c.dl_in.fetch_add(samples.len() as u64, Relaxed);
                        }
                        buf.extend(samples);
                        break;
                    }
                    Err(zmq::Error::EAGAIN) => {
                        // 2 s receive timeout: report a stalled upstream.
                        eprintln!("{name}: upstream port {p} silent for 2 s");
                        continue;
                    }
                    Err(e) => return Err(format!("upstream: {e}")),
                }
            }
        }
        let n = pending.iter().map(Vec::len).min().unwrap_or(0);
        let refs: Vec<&[Complex32]> = pending.iter().map(|b| &b[..n]).collect();
        let t1 = Instant::now();
        let outs = link.process(&refs);
        pending.iter_mut().for_each(|b| {
            b.drain(..n);
        });
        let t2 = Instant::now();
        // An empty output (start-up look-ahead) is not queued: the
        // downstream side must never receive a zero-length block.
        if outs.first().is_some_and(|o| !o.is_empty()) {
            depth.push()?;
            for (tx, out) in txs.iter().zip(outs) {
                tx.send(out).map_err(|_| "downstream gone".to_string())?;
            }
        }
        t_up += (t1 - t0).as_secs_f64();
        t_proc += (t2 - t1).as_secs_f64();
        t_down += t2.elapsed().as_secs_f64();
        n_blocks += 1;
        if report.elapsed().as_secs() >= 10 {
            let dt = report.elapsed().as_secs_f64();
            report = Instant::now();
            let p = link
                .signal_power()
                .map_or("-".into(), |p| format!("{:.1} dBFS", 10.0 * p.log10()));
            eprintln!(
                "{name}: {} samples in, {} out, signal {p}, pace {:.2}× real time; {} blocks of {:.0} samples, waiting upstream {:.0} %, processing {:.0} %, waiting downstream {:.0} %",
                link.samples_in(),
                link.samples_out(),
                (link.samples_in() - last_in) as f64 / dt / link.config().fs,
                n_blocks,
                (link.samples_in() - last_in) as f64 / n_blocks.max(1) as f64,
                100.0 * t_up / dt,
                100.0 * t_proc / dt,
                100.0 * t_down / dt
            );
            (t_up, t_proc, t_down, n_blocks) = (0.0, 0.0, 0.0, 0);
            last_in = link.samples_in();
        }
    }
}

/// Throughput of the downlink channel on noise (samples per second).
fn bench(a: &Args) -> Result<(), String> {
    let (dl, _) = links(a, a.antennas)?;
    let mut link = Link::new(dl);
    let mut rng = ferrite_radio::channel::Rng::new(3);
    let block: Vec<Vec<Complex32>> = (0..a.antennas)
        .map(|_| (0..1920).map(|_| rng.cgauss()).collect())
        .collect();
    let total = (a.bench_s.unwrap_or(1.0) * a.srate_hz) as usize;
    let t0 = Instant::now();
    let mut done = 0;
    while done < total {
        let refs: Vec<&[Complex32]> = block.iter().map(Vec::as_slice).collect();
        link.process(&refs);
        done += 1920;
    }
    let rate = done as f64 / t0.elapsed().as_secs_f64();
    println!(
        "{} antenna(s), model {:?}: {:.2} Msps ({:.2}× real time at {:.2} MHz)",
        a.antennas,
        a.model,
        rate / 1e6,
        rate / a.srate_hz,
        a.srate_hz / 1e6
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let a = parse()?;
    if a.bench_s.is_some() {
        return bench(&a);
    }
    if a.dl_up.is_empty()
        || a.dl_up.len() != a.dl_bind.len()
        || a.ul_up.len() != 1
        || a.ul_bind.len() != 1
    {
        return Err(format!(
            "need matching --dl-up/--dl-bind lists and one --ul-up/--ul-bind\n{USAGE}"
        ));
    }
    let (dl, ul) = links(&a, a.dl_up.len())?;
    eprintln!(
        "ferrite-chanem: model {:?} (ds {:.0} ns, doppler {} Hz), delay {:.0} ns, UE clock {:+} ppm (DL CFO {:+.0} Hz, UL CFO {:+.0} Hz), SNR DL {:?} UL {:?} dB",
        a.model, a.ds_s * 1e9, a.doppler_hz, a.delay_s * 1e9, a.ppm, dl.cfo_hz, ul.cfo_hz, a.dl_snr_db, a.ul_snr_db
    );
    let ctx = zmq::Context::new();
    let coupling = Arc::new(Coupling {
        dl_in: AtomicU64::new(0),
        ul_out: AtomicU64::new(0),
        // 5 ms: well inside the gNB's receive buffer, well beyond its
        // transmit advance and the uplink pipeline.
        margin: (a.srate_hz * 5e-3) as u64,
    });
    let ul_thread = {
        let ctx = ctx.clone();
        let coupling = Arc::clone(&coupling);
        let (up, bind) = (a.ul_up.clone(), a.ul_bind.clone());
        std::thread::Builder::new()
            .name("chanem-ul".into())
            .spawn(move || serve("UL", Dir::Ul, &coupling, &ctx, &up, &bind, Link::new(ul)))
            .map_err(|e| format!("thread: {e}"))?
    };
    let dl_result = serve(
        "DL",
        Dir::Dl,
        &coupling,
        &ctx,
        &a.dl_up,
        &a.dl_bind,
        Link::new(dl),
    );
    // The DL loop only returns on an error; report it (and the UL one).
    let ul_result = if ul_thread.is_finished() {
        ul_thread
            .join()
            .unwrap_or_else(|_| Err("UL thread panicked".into()))
    } else {
        Ok(())
    };
    dl_result.and(ul_result)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ferrite-chanem: {e}");
            ExitCode::from(2)
        }
    }
}
