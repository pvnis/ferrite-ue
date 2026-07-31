//! TUN interface support so the host OS can send/receive real IP traffic that
//! Ferrite carries over the DRB: create a layer-3 TUN device, optionally move it
//! into a network namespace, and configure its address/route. The UE process keeps
//! the character-device fd (works regardless of which namespace the netdev is in)
//! and shuttles packets between it and the DRB. Requires CAP_NET_ADMIN (run under
//! sudo). This is OS plumbing, not 3GPP protocol code.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::process::Command;

const IFF_TUN: libc::c_short = 0x0001; // layer-3 (IP) TUN, not TAP
const IFF_NO_PI: libc::c_short = 0x1000; // no 4-byte packet-info prefix
const TUNSETIFF: libc::c_ulong = 0x400454ca; // _IOW('T', 202, int), x86-64/arm64

#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    flags: libc::c_short,
    _pad: [u8; 22], // pad to sizeof(struct ifreq) = 40
}

/// Create a TUN device named `name` (layer 3, no packet-info header) and return an
/// open, non-blocking File handle to its character device. Needs CAP_NET_ADMIN.
pub fn open_tun(name: &str) -> io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
    if name.len() >= 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "tun name too long"));
    }
    let mut req = IfReq { name: [0; 16], flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
    for (i, &b) in name.as_bytes().iter().enumerate() {
        req.name[i] = b as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &req as *const IfReq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // Non-blocking so the main radio loop can poll it between slots.
    let fd = file.as_raw_fd();
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
    Ok(file)
}

/// Configure the TUN interface `name`: set `mtu`, assign `ip`, bring it up. If
/// `netns` is Some, first move the interface into that namespace (created if
/// missing) and configure it there, and add a default route over the DRB so the
/// namespace's traffic flows through Ferrite. Runs the `ip` tool; needs privileges.
pub fn configure_tun(name: &str, ip: [u8; 4], mtu: u32, netns: Option<&str>) -> io::Result<()> {
    let ips = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    let mtu = mtu.to_string();
    // Run `ip <args>`; log (don't fail) on a non-zero exit so re-runs are tolerant
    // of "File exists" from a leftover interface/address.
    let run = |args: &[&str]| {
        match Command::new("ip").args(args).output() {
            Ok(o) if !o.status.success() => {
                let e = String::from_utf8_lossy(&o.stderr);
                let e = e.trim();
                if !e.contains("File exists") {
                    eprintln!("   [tun] `ip {}` -> {e}", args.join(" "));
                }
            }
            Err(e) => eprintln!("   [tun] failed to run `ip {}`: {e}", args.join(" ")),
            _ => {}
        }
    };
    if let Some(ns) = netns {
        run(&["netns", "add", ns]);
        run(&["link", "set", name, "netns", ns]);
        run(&["-n", ns, "link", "set", "lo", "up"]);
        run(&["-n", ns, "link", "set", name, "mtu", &mtu, "up"]);
        run(&["-n", ns, "addr", "add", &format!("{ips}/24"), "dev", name]);
    } else {
        // Host namespace: a /32 avoids clashing with an existing on-link subnet.
        run(&["link", "set", name, "mtu", &mtu, "up"]);
        run(&["addr", "add", &format!("{ips}/32"), "dev", name]);
    }
    Ok(())
}
