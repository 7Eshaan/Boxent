//! `boxent doctor`: checks the kernel features and tools the engine depends on, with a fix for
//! each failure.

#[cfg(not(target_os = "linux"))]
mod host;
#[cfg(target_os = "linux")]
mod linux;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub struct Options {
    pub json: bool,
    pub host_only: bool,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    pub fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, Status::Pass, detail, None)
    }

    pub fn warn(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(name, Status::Warn, detail, Some(fix.into()))
    }

    pub fn fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(name, Status::Fail, detail, Some(fix.into()))
    }

    fn new(name: &str, status: Status, detail: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            name: name.to_owned(),
            status,
            detail: detail.into(),
            fix,
        }
    }
}

/// A group of checks that ran in one place (the macOS host or a Linux kernel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub scope: String,
    pub checks: Vec<Check>,
}

/// Runs the checks that apply to this machine. Returns `Ok(true)` when nothing failed.
pub fn run(opts: &Options) -> anyhow::Result<bool> {
    let sections = collect(opts);
    if opts.json {
        println!("{}", serde_json::to_string_pretty(&sections)?);
    } else {
        print_human(&sections);
    }
    Ok(sections
        .iter()
        .flat_map(|s| &s.checks)
        .all(|c| c.status != Status::Fail))
}

#[cfg(target_os = "linux")]
fn collect(opts: &Options) -> Vec<Section> {
    let _ = opts.host_only;
    vec![Section {
        scope: "linux".to_owned(),
        checks: linux::checks(&opts.data_dir),
    }]
}

#[cfg(not(target_os = "linux"))]
fn collect(opts: &Options) -> Vec<Section> {
    let _ = &opts.data_dir;
    let mut sections = vec![Section {
        scope: "macos-host".to_owned(),
        checks: host::checks(),
    }];
    if !opts.host_only {
        sections.push(host::vm_section());
    }
    sections
}

fn print_human(sections: &[Section]) {
    for section in sections {
        println!("{}", section.scope);
        for check in &section.checks {
            let tag = match check.status {
                Status::Pass => "PASS",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
            };
            println!("  [{tag}] {}: {}", check.name, check.detail);
            if let Some(fix) = &check.fix {
                println!("         fix: {fix}");
            }
        }
    }
    let all: Vec<&Check> = sections.iter().flat_map(|s| &s.checks).collect();
    let count = |st| all.iter().filter(|c| c.status == st).count();
    println!(
        "\n{} passed, {} warnings, {} failed",
        count(Status::Pass),
        count(Status::Warn),
        count(Status::Fail)
    );
}

/// Parses the leading `major.minor` of a kernel release string such as `6.8.0-45-generic`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Returns the cgroup v2 controllers from `required` that are absent from a
/// `cgroup.controllers` listing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn missing_controllers<'a>(listing: &str, required: &[&'a str]) -> Vec<&'a str> {
    let present: Vec<&str> = listing.split_whitespace().collect();
    required
        .iter()
        .copied()
        .filter(|c| !present.contains(c))
        .collect()
}

/// Formats 16 raw bytes as a lowercase, hyphenated UUID (the form used under `/sys/fs/btrfs`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Extracts `x.y.z` from `limactl --version` output such as `limactl version 2.3.0`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn parse_lima_version(output: &str) -> Option<(u32, u32, u32)> {
    let word = output.split_whitespace().last()?;
    let mut nums = word.trim_start_matches('v').split('.').map(str::parse);
    match (nums.next(), nums.next(), nums.next()) {
        (Some(Ok(a)), Some(Ok(b)), Some(Ok(c))) => Some((a, b, c)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release_variants() {
        assert_eq!(parse_kernel_release("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_release("7.0.1"), Some((7, 0)));
        assert_eq!(
            parse_kernel_release("6.6.87.2-microsoft-standard-WSL2"),
            Some((6, 6))
        );
        assert_eq!(parse_kernel_release("garbage"), None);
    }

    #[test]
    fn controllers() {
        let listing = "cpuset cpu io memory hugetlb pids rdma misc\n";
        assert!(missing_controllers(listing, &["cpu", "memory", "pids", "io"]).is_empty());
        assert_eq!(
            missing_controllers("cpu memory", &["cpu", "memory", "pids"]),
            vec!["pids"]
        );
    }

    #[test]
    fn uuid_format() {
        let bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(format_uuid(&bytes), "12345678-9abc-def0-0123-456789abcdef");
    }

    #[test]
    fn lima_version() {
        assert_eq!(
            parse_lima_version("limactl version 2.3.0\n"),
            Some((2, 3, 0))
        );
        assert_eq!(
            parse_lima_version("limactl version v1.0.7"),
            Some((1, 0, 7))
        );
        assert_eq!(parse_lima_version(""), None);
    }

    #[test]
    fn report_round_trips_as_json() {
        let section = Section {
            scope: "linux".into(),
            checks: vec![
                Check::pass("kernel", "6.8"),
                Check::fail("btrfs", "missing", "mount it"),
            ],
        };
        let text = serde_json::to_string(&vec![section]).unwrap();
        let back: Vec<Section> = serde_json::from_str(&text).unwrap();
        assert_eq!(back[0].checks[1].status, Status::Fail);
        assert_eq!(back[0].checks[1].fix.as_deref(), Some("mount it"));
        assert!(back[0].checks[0].fix.is_none());
    }
}
