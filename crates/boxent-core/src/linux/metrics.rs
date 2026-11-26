//! Counters for `/metrics` (Prometheus text format). Plain atomics: no registry, no locks.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ReapReason;

/// Upper bounds of the command-duration histogram, in milliseconds.
const BUCKETS_MS: [u64; 11] = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 10_000, 60_000];

#[derive(Default)]
pub struct Metrics {
    execs: AtomicU64,
    exec_timeouts: AtomicU64,
    exec_oom_kills: AtomicU64,
    exec_buckets: [AtomicU64; BUCKETS_MS.len()],
    exec_ms_sum: AtomicU64,
    snapshots: AtomicU64,
    restores: AtomicU64,
    reaped: [AtomicU64; ReapReason::ALL.len()],
}

/// Point-in-time values the engine adds when rendering.
pub struct Gauges {
    pub warm: usize,
    pub active: usize,
    pub provisioning: usize,
    pub claims_warm: u64,
    pub claims_cold: u64,
    pub created: u64,
    pub create_failures: u64,
    pub egress_allowed: u64,
    pub egress_denied: u64,
}

impl Metrics {
    pub fn exec(&self, duration_ms: u64, timed_out: bool, oom_killed: bool) {
        self.execs.fetch_add(1, Ordering::Relaxed);
        self.exec_ms_sum.fetch_add(duration_ms, Ordering::Relaxed);
        if timed_out {
            self.exec_timeouts.fetch_add(1, Ordering::Relaxed);
        }
        if oom_killed {
            self.exec_oom_kills.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(i) = BUCKETS_MS.iter().position(|b| duration_ms <= *b) {
            self.exec_buckets[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) {
        self.snapshots.fetch_add(1, Ordering::Relaxed);
    }

    pub fn restore(&self) {
        self.restores.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reaped(&self, reason: ReapReason) {
        let i = ReapReason::ALL
            .iter()
            .position(|r| *r == reason)
            .unwrap_or(0);
        self.reaped[i].fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self, g: &Gauges) -> String {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut out = String::new();
        let mut metric = |name: &str, kind: &str, help: &str, lines: &[(String, u64)]| {
            let _ = writeln!(
                out,
                "# HELP boxent_{name} {help}\n# TYPE boxent_{name} {kind}"
            );
            for (labels, v) in lines {
                let _ = writeln!(out, "boxent_{name}{labels} {v}");
            }
        };
        let one = |v: u64| vec![(String::new(), v)];
        metric(
            "sandboxes",
            "gauge",
            "Sandboxes by state.",
            &[
                ("{state=\"warm\"}".into(), g.warm as u64),
                ("{state=\"active\"}".into(), g.active as u64),
                ("{state=\"provisioning\"}".into(), g.provisioning as u64),
            ],
        );
        metric(
            "claims_total",
            "counter",
            "Sandbox claims, by whether a warm sandbox was ready.",
            &[
                ("{source=\"warm\"}".into(), g.claims_warm),
                ("{source=\"cold\"}".into(), g.claims_cold),
            ],
        );
        metric(
            "sandboxes_created_total",
            "counter",
            "Sandboxes created.",
            &one(g.created),
        );
        metric(
            "sandbox_create_failures_total",
            "counter",
            "Failed sandbox creations.",
            &one(g.create_failures),
        );
        let reaped: Vec<(String, u64)> = ReapReason::ALL
            .iter()
            .enumerate()
            .map(|(i, r)| {
                (
                    format!("{{reason=\"{}\"}}", r.as_str()),
                    load(&self.reaped[i]),
                )
            })
            .collect();
        metric(
            "sandboxes_reaped_total",
            "counter",
            "Sandboxes reaped, by reason.",
            &reaped,
        );
        metric(
            "exec_timeouts_total",
            "counter",
            "Commands killed at their timeout.",
            &one(load(&self.exec_timeouts)),
        );
        metric(
            "exec_oom_kills_total",
            "counter",
            "Commands killed for exceeding the memory limit.",
            &one(load(&self.exec_oom_kills)),
        );
        metric(
            "snapshots_total",
            "counter",
            "Snapshots taken.",
            &one(load(&self.snapshots)),
        );
        metric(
            "restores_total",
            "counter",
            "Snapshot restores.",
            &one(load(&self.restores)),
        );
        metric(
            "egress_requests_total",
            "counter",
            "Egress proxy decisions.",
            &[
                ("{decision=\"allowed\"}".into(), g.egress_allowed),
                ("{decision=\"denied\"}".into(), g.egress_denied),
            ],
        );
        let mut cumulative = 0;
        let mut hist: Vec<(String, u64)> = BUCKETS_MS
            .iter()
            .enumerate()
            .map(|(i, b)| {
                cumulative += load(&self.exec_buckets[i]);
                (
                    format!("_bucket{{le=\"{}\"}}", *b as f64 / 1000.0),
                    cumulative,
                )
            })
            .collect();
        let count = load(&self.execs);
        hist.push(("_bucket{le=\"+Inf\"}".into(), count));
        hist.push(("_sum".into(), load(&self.exec_ms_sum) / 1000));
        hist.push(("_count".into(), count));
        metric(
            "exec_duration_seconds",
            "histogram",
            "Command run time inside the sandbox.",
            &hist,
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::default();
        m.exec(3, false, false);
        m.exec(700, true, false);
        m.reaped(ReapReason::Idle);
        let g = Gauges {
            warm: 4,
            active: 1,
            provisioning: 0,
            claims_warm: 2,
            claims_cold: 1,
            created: 5,
            create_failures: 0,
            egress_allowed: 7,
            egress_denied: 3,
        };
        let text = m.render(&g);
        for want in [
            "boxent_sandboxes{state=\"warm\"} 4",
            "boxent_sandboxes_reaped_total{reason=\"idle\"} 1",
            "boxent_exec_timeouts_total 1",
            "boxent_exec_duration_seconds_bucket{le=\"0.005\"} 1",
            "boxent_exec_duration_seconds_bucket{le=\"1\"} 2",
            "boxent_exec_duration_seconds_count 2",
            "boxent_egress_requests_total{decision=\"denied\"} 3",
        ] {
            assert!(text.contains(want), "missing {want}\n{text}");
        }
    }
}
