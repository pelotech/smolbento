//! Parsing sbx's create-time options: ports, memory, CPUs and environment.

use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::smolvm::PortMap;

/// Parses sbx's `[[IP:]HOST:]PORT[/proto]`. A missing host port gets a free one.
pub fn parse_publish(spec: &str, free_port: &dyn Fn() -> Result<u16>) -> Result<PortMap> {
    let (body, udp) = match spec.rsplit_once('/') {
        Some((b, "tcp")) => (b, false),
        Some((b, "udp")) => (b, true),
        Some((_, p)) => bail!("unknown protocol '{p}' in '{spec}' (use tcp or udp)"),
        None => (spec, false),
    };
    let parts: Vec<&str> = body.split(':').collect();
    let (ip, host, guest) = match parts.as_slice() {
        [g] => (None, None, *g),
        [h, g] => (None, Some(*h), *g),
        [ip, h, g] => (Some(*ip), Some(*h), *g),
        _ => bail!("invalid port '{spec}'; expected [[IP:]HOST:]PORT[/proto]"),
    };
    if let Some(ip) = ip
        && ip != "127.0.0.1"
        && ip != "localhost"
    {
        bail!("can't bind {ip}: smolvm publishes on 127.0.0.1 only");
    }
    let guest = parse_port(guest, spec)?;
    let host = match host {
        Some(h) if !h.is_empty() => parse_port(h, spec)?,
        _ => free_port()?,
    };
    Ok(PortMap { host, guest, udp })
}

fn parse_port(value: &str, spec: &str) -> Result<u16> {
    match value.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => bail!("invalid port '{value}' in '{spec}'"),
    }
}

pub fn free_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("finding a free port")?;
    Ok(listener.local_addr()?.port())
}

/// Parses `4g`, `512m`, `512MiB` or a byte count into MiB (minimum 512).
pub fn parse_memory(value: &str) -> Result<u64> {
    let mib = parse_size(value, "memory")? >> 20;
    if mib < 512 {
        bail!("memory must be at least 512MiB, got '{value}'");
    }
    Ok(mib)
}

/// Parses `40g`, `512m`, `1TiB` or a byte count into bytes; `what` names the value in errors.
pub fn parse_size(value: &str, what: &str) -> Result<u64> {
    let v = value.trim().to_ascii_lowercase();
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid {what} '{value}'"))?;
    let shift = match unit.trim_end_matches(['b', 'i']) {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => bail!("invalid {what} unit in '{value}' (use k, m, g or t)"),
    };
    n.checked_mul(1 << shift)
        .with_context(|| format!("{what} '{value}' is too large"))
}

/// sbx's default: half of host memory, clamped to 512 MiB–32 GiB.
pub fn default_memory_mib(host_mib: u64) -> u64 {
    (host_mib / 2).clamp(512, 32768)
}

pub fn host_memory_mib() -> Result<u64> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .context("running sysctl")?;
        let bytes: u64 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .context("parsing hw.memsize")?;
        Ok(bytes >> 20)
    }
    #[cfg(target_os = "linux")]
    {
        let info = fs::read_to_string("/proc/meminfo").context("reading /proc/meminfo")?;
        let kb: u64 = info
            .lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .context("MemTotal missing from /proc/meminfo")?;
        Ok(kb >> 10)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        bail!("reading host memory is not supported on this platform")
    }
}

/// sbx's `--cpus 0` means all host CPUs.
pub fn host_cpus() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u32)
}

/// `--env-file` lines, then `-e` items. `KEY=VALUE` is taken as is; a bare `KEY` copies the
/// host's value and is skipped when the host doesn't have it.
pub fn parse_env(
    items: &[String],
    files: &[PathBuf],
    host: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut add = |item: &str| match item.split_once('=') {
        Some((k, v)) if !k.is_empty() => out.push((k.to_string(), v.to_string())),
        Some(_) => {}
        None => {
            if let Some(v) = host.get(item) {
                out.push((item.to_string(), v.clone()));
            }
        }
    };
    for file in files {
        let text =
            fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            add(line);
        }
    }
    for item in items {
        add(item);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> Result<u16> {
        Ok(40000)
    }

    #[test]
    fn publish_forms() {
        assert_eq!(
            parse_publish("80", &fixed).unwrap(),
            PortMap {
                host: 40000,
                guest: 80,
                udp: false
            }
        );
        assert_eq!(
            parse_publish("8080:80", &fixed).unwrap(),
            PortMap {
                host: 8080,
                guest: 80,
                udp: false
            }
        );
        assert_eq!(
            parse_publish("127.0.0.1:3000:3000/tcp", &fixed)
                .unwrap()
                .host,
            3000
        );
        assert_eq!(
            parse_publish("127.0.0.1::53/udp", &fixed).unwrap(),
            PortMap {
                host: 40000,
                guest: 53,
                udp: true
            }
        );
        assert!(
            parse_publish("0.0.0.0:80:80", &fixed)
                .unwrap_err()
                .to_string()
                .contains("127.0.0.1 only")
        );
        assert!(parse_publish("80/sctp", &fixed).is_err());
        assert!(parse_publish("0", &fixed).is_err());
    }

    #[test]
    fn memory_units() {
        assert_eq!(parse_memory("4g").unwrap(), 4096);
        assert_eq!(parse_memory("512MiB").unwrap(), 512);
        assert_eq!(parse_memory("1073741824").unwrap(), 1024);
        assert!(
            parse_memory("256m")
                .unwrap_err()
                .to_string()
                .contains("at least 512")
        );
        assert!(parse_memory("lots").is_err());
        assert!(parse_memory("99999999999999t").is_err());
    }

    #[test]
    fn size_units() {
        assert_eq!(parse_size("40g", "size").unwrap(), 40 << 30);
        assert_eq!(parse_size("1TiB", "size").unwrap(), 1 << 40);
        assert_eq!(parse_size(" 7 ", "size").unwrap(), 7);
        let err = parse_size("20x", "cache size").unwrap_err().to_string();
        assert!(err.contains("invalid cache size unit"), "{err}");
        assert!(parse_size("", "size").is_err());
        assert!(parse_size("-1g", "size").is_err());
    }

    #[test]
    fn default_memory_is_half_clamped() {
        assert_eq!(default_memory_mib(16384), 8192);
        assert_eq!(default_memory_mib(512), 512);
        assert_eq!(default_memory_mib(131072), 32768);
    }

    #[test]
    fn env_from_flags_files_and_host() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        std::fs::write(&file, "# comment\nA=1\n\nHOSTONLY\n").unwrap();
        let host = BTreeMap::from([
            ("HOSTONLY".to_string(), "h".to_string()),
            ("B".to_string(), "b".to_string()),
        ]);
        let env = parse_env(
            &["C=3".into(), "B".into(), "MISSING".into()],
            &[file],
            &host,
        )
        .unwrap();
        let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(
            pairs,
            vec![("A", "1"), ("HOSTONLY", "h"), ("C", "3"), ("B", "b")]
        );
    }

    #[test]
    fn host_facts_are_positive() {
        assert!(host_cpus() >= 1);
        assert!(host_memory_mib().unwrap() >= 512);
        assert_ne!(free_port().unwrap(), 0);
    }
}
