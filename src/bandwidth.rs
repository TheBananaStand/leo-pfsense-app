//! Live network throughput — router WAN/LAN only.
//!
//! This is the router half of `leo_services::bandwidth`, kept verbatim.
//! The hub-NIC (`/proc/net/dev`) half is deliberately absent: that measures
//! the hub machine, which lives in the hub. A subprocess reporting the hub's
//! own traffic as "WAN" would be wrong, and carrying `/proc/net/dev` here
//! would make the hub-half of the monitor unreachable from the bandwidth API
//! (which still lives on the hub).
//!
//! Everything here — `Sampler`, `Counters`, `Rate`, `Snapshot`,
//! `BandwidthMonitor`, and both parse functions — is copied from the original
//! without changes so that tests can be ported identically.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Cumulative byte counters for one interface (or a set of them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Throughput in bits per second — the unit link speeds are quoted in, so a
/// reading is directly comparable to "1 Gbps" without the reader doing mental
/// arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Rate {
    pub down_bps: f64,
    pub up_bps: f64,
}

/// Turns successive cumulative readings into a rate.
#[derive(Debug, Default)]
pub struct Sampler {
    prev: Mutex<Option<(Instant, Counters)>>,
}

impl Sampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a reading, returning the rate since the previous one.
    ///
    /// `None` on the first reading (nothing to compare against) and whenever
    /// the counters went backwards — a router reboot or a 32-bit counter wrap
    /// would otherwise show up as an absurd spike. Dropping the sample and
    /// re-basing costs one interval and can't lie.
    pub fn observe(&self, at: Instant, now: Counters) -> Option<Rate> {
        let mut guard = self.prev.lock().unwrap_or_else(|e| e.into_inner());
        let previous = guard.replace((at, now));

        let (then, before) = previous?;
        let elapsed = at.checked_duration_since(then)?.as_secs_f64();
        if elapsed <= 0.0 {
            return None;
        }
        let rx = now.rx_bytes.checked_sub(before.rx_bytes)?;
        let tx = now.tx_bytes.checked_sub(before.tx_bytes)?;

        Some(Rate {
            down_bps: (rx as f64) * 8.0 / elapsed,
            up_bps: (tx as f64) * 8.0 / elapsed,
        })
    }
}

/// What the API hands to clients. Every field is optional because each source
/// can be unavailable independently — pfSense not configured, unreachable, or
/// simply not sampled twice yet.
///
/// Note: `hub` is absent here. The hub reports its own NIC rates directly; a
/// subprocess reporting them would be measuring a different machine.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    /// The internet link, measured at the edge router.
    pub wan: Option<Rate>,
    /// Traffic across the router's LAN interface.
    pub lan: Option<Rate>,
    /// Why `wan`/`lan` are missing, when they are. Shown to the user rather
    /// than leaving a card blank with no explanation.
    pub router_error: Option<String>,
    /// Seconds since the last successful sample, so a client can tell "idle
    /// link" from "sampler is dead".
    pub age_secs: Option<u64>,
}

/// Holds the samplers and the latest computed snapshot.
#[derive(Debug, Default)]
pub struct BandwidthMonitor {
    wan: Sampler,
    lan: Sampler,
    latest: Mutex<Snapshot>,
    last_update: Mutex<Option<Instant>>,
}

impl BandwidthMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sample the router's WAN and LAN interfaces from one `netstat -ibn`.
    pub fn record_router(&self, netstat: &str, wan_if: &str, lan_if: &str) {
        let at = Instant::now();
        let mut latest = self.latest.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = parse_netstat_ibn(netstat, wan_if)
            && let Some(r) = self.wan.observe(at, c)
        {
            latest.wan = Some(r);
        }
        if let Some(c) = parse_netstat_ibn(netstat, lan_if)
            && let Some(r) = self.lan.observe(at, c)
        {
            latest.lan = Some(r);
        }
        latest.router_error = None;
        drop(latest);
        self.touch();
    }

    /// Note that the router couldn't be reached, so the UI can say why rather
    /// than showing a stale rate forever.
    pub fn record_router_error(&self, message: impl Into<String>) {
        let mut latest = self.latest.lock().unwrap_or_else(|e| e.into_inner());
        latest.wan = None;
        latest.lan = None;
        latest.router_error = Some(message.into());
    }

    fn touch(&self) {
        *self.last_update.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    /// The latest rates.
    pub fn snapshot(&self) -> Snapshot {
        let mut out = self
            .latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        out.age_secs = self
            .last_update
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed().as_secs());
        out
    }
}

/// How often the router is sampled. An SSH handshake per sample makes this the
/// expensive source, so it ticks slower than the link changes — enough to see
/// a download start, not enough to be a load on the firewall.
pub const ROUTER_INTERVAL: Duration = Duration::from_secs(10);

/// Pull one interface's byte counters out of FreeBSD `netstat -ibn`.
///
/// The command prints several rows per interface — one per configured address
/// plus a `<Link#N>` row. Only the `<Link#N>` row carries the interface totals;
/// the per-address rows count just that address's traffic, so matching the
/// first row for the name (as a naive parse would) undercounts badly.
pub fn parse_netstat_ibn(text: &str, iface: &str) -> Option<Counters> {
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        let (Some(name), Some(_mtu), Some(network)) = (cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if name != iface || !network.starts_with("<Link") {
            continue;
        }
        // Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes [Coll]
        let rest: Vec<&str> = cols.collect();
        // Skip the link-layer address, then index into the counters.
        let rx = rest.get(4)?.parse().ok()?;
        let tx = rest.get(7)?.parse().ok()?;
        return Some(Counters {
            rx_bytes: rx,
            tx_bytes: tx,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real shape of `netstat -ibn` on pfSense.
    const NETSTAT: &str = "\
Name       Mtu Network           Address                               Ipkts Ierrs Idrop         Ibytes       Opkts Oerrs         Obytes  Coll
igb0      1500 <Link#1>          00:e0:97:1d:6f:06                5521092196     0     0  5054048490540  3565029599     0  2830555584579     0
igb0         - fe80::%igb0/64    fe80::2e0:97ff:fe1d:6f06%igb0             0     -     -              0       58082     -        6737124     -
igb0         - 47.153.97.0/24    47.153.97.66                       12357193     -     -     2955791964     4488091     -      130977633     -
igb1      1500 <Link#2>          00:e0:97:1d:6f:07                3546074999     0     0  2829045500926  5495573989     0  5049243172407     0
";

    #[test]
    fn netstat_reads_the_link_row_not_the_per_address_rows() {
        let wan = parse_netstat_ibn(NETSTAT, "igb0").unwrap();
        assert_eq!(wan.rx_bytes, 5_054_048_490_540);
        assert_eq!(wan.tx_bytes, 2_830_555_584_579);

        let lan = parse_netstat_ibn(NETSTAT, "igb1").unwrap();
        assert_eq!(lan.rx_bytes, 2_829_045_500_926);
        assert_eq!(lan.tx_bytes, 5_049_243_172_407);
    }

    #[test]
    fn an_unknown_interface_is_none_not_a_wrong_answer() {
        assert!(parse_netstat_ibn(NETSTAT, "igb9").is_none());
        assert!(parse_netstat_ibn("", "igb0").is_none());
    }

    #[test]
    fn the_first_reading_has_no_rate_and_the_second_does() {
        let s = Sampler::new();
        let t0 = Instant::now();
        assert!(
            s.observe(
                t0,
                Counters {
                    rx_bytes: 0,
                    tx_bytes: 0
                }
            )
            .is_none()
        );

        let r = s
            .observe(
                t0 + Duration::from_secs(8),
                Counters {
                    rx_bytes: 1_000_000,
                    tx_bytes: 500_000,
                },
            )
            .unwrap();
        assert!((r.down_bps - 1_000_000.0).abs() < 1.0);
        assert!((r.up_bps - 500_000.0).abs() < 1.0);
    }

    #[test]
    fn counters_going_backwards_are_dropped_not_reported_as_a_spike() {
        let s = Sampler::new();
        let t0 = Instant::now();
        s.observe(
            t0,
            Counters {
                rx_bytes: 9_000,
                tx_bytes: 9_000,
            },
        );
        let after_reboot = s.observe(
            t0 + Duration::from_secs(10),
            Counters {
                rx_bytes: 10,
                tx_bytes: 10,
            },
        );
        assert!(after_reboot.is_none());

        let r = s
            .observe(
                t0 + Duration::from_secs(20),
                Counters {
                    rx_bytes: 1_010,
                    tx_bytes: 10,
                },
            )
            .unwrap();
        assert!((r.down_bps - 800.0).abs() < 1.0);
    }

    #[test]
    fn a_monitor_with_no_samples_reports_every_source_absent() {
        let m = BandwidthMonitor::new();
        let s = m.snapshot();
        assert!(s.wan.is_none() && s.lan.is_none());
        assert!(s.age_secs.is_none());
    }

    #[test]
    fn the_router_needs_two_samples_before_it_reports() {
        let m = BandwidthMonitor::new();
        m.record_router(NETSTAT, "igb0", "igb1");
        assert!(m.snapshot().wan.is_none(), "first sample is only a baseline");

        m.record_router(NETSTAT, "igb0", "igb1");
        let s = m.snapshot();
        assert_eq!(s.wan.unwrap().down_bps, 0.0);
        assert!(s.age_secs.is_some());
    }

    #[test]
    fn an_unreachable_router_clears_the_rates_and_says_why() {
        let m = BandwidthMonitor::new();
        m.record_router(NETSTAT, "igb0", "igb1");
        m.record_router(NETSTAT, "igb0", "igb1");
        assert!(m.snapshot().wan.is_some());

        m.record_router_error("SSH connect failed");
        let s = m.snapshot();
        assert!(s.wan.is_none() && s.lan.is_none());
        assert_eq!(s.router_error.as_deref(), Some("SSH connect failed"));
    }
}
