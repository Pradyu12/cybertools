//! Target expansion.
//!
//! Accepted input forms (comma-separated or repeated `-a` flags):
//! - a single IPv4/IPv6 address: `192.168.1.5`
//! - a hostname: `example.com` (resolved via DNS, all addresses scanned)
//! - a CIDR block: `192.168.1.0/24`
//! - an IP range: `192.168.1.5-192.168.1.20`
//! - an octet range: `192.168.1.5-20`
//! - a file of targets (one per line, `#` comments allowed): `@targets.txt`

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use thiserror::Error;

/// A single resolved scan target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedHost {
    pub ip: IpAddr,
    /// Original hostname, when the target was given as a name rather than an IP.
    pub hostname: Option<String>,
}

/// Errors produced while expanding targets.
#[derive(Debug, Error)]
pub enum TargetError {
    #[error("invalid target `{0}`: {1}")]
    Invalid(String, String),
    #[error("target `{0}` expands to {1} addresses, exceeding the limit of {2}")]
    TooLarge(String, u64, u64),
    #[error("failed to resolve hostname `{0}`")]
    Resolve(String),
    #[error("failed to read target file `{0}`: {1}")]
    ReadFile(String, String),
}

/// Upper bound on how many addresses a single target may expand to.
pub const MAX_TARGETS: u64 = 65_536;

/// Expand a CIDR block into its host addresses (network and broadcast
/// addresses are excluded, except for /31 and /32 which are fully returned).
pub fn parse_cidr(spec: &str) -> Result<Vec<IpAddr>, TargetError> {
    let net: IpNet = spec
        .parse()
        .map_err(|_| TargetError::Invalid(spec.into(), "not a valid CIDR block".into()))?;
    let count = net.hosts().count() as u64;
    if count > MAX_TARGETS {
        return Err(TargetError::TooLarge(spec.into(), count, MAX_TARGETS));
    }
    Ok(net.hosts().collect())
}

/// Expand an IP or octet range (`192.168.1.5-192.168.1.9` or `192.168.1.5-9`)
/// into its addresses.
pub fn parse_ip_range(spec: &str) -> Result<Vec<IpAddr>, TargetError> {
    let (a, b) = spec
        .split_once('-')
        .ok_or_else(|| TargetError::Invalid(spec.into(), "no '-' found in range".into()))?;
    let a = a.trim();
    let b = b.trim();

    // Octet range: "192.168.1.5-9"
    if let Ok(right_octet) = b.parse::<u8>() {
        let base: IpAddr = a
            .parse()
            .map_err(|_| TargetError::Invalid(spec.into(), "left side is not an IP address".into()))?;
        let IpAddr::V4(v4) = base else {
            return Err(TargetError::Invalid(
                spec.into(),
                "octet ranges are only supported for IPv4".into(),
            ));
        };
        let octets = v4.octets();
        let mut out = Vec::with_capacity((right_octet - octets[3] + 1) as usize);
        for last in octets[3]..=right_octet {
            out.push(IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], last)));
        }
        return Ok(out);
    }

    // Full IP range: "192.168.1.5-192.168.1.9"
    let start: IpAddr = a
        .parse()
        .map_err(|_| TargetError::Invalid(spec.into(), "left side is not an IP address".into()))?;
    let end: IpAddr = b
        .parse()
        .map_err(|_| TargetError::Invalid(spec.into(), "right side is not an IP address".into()))?;
    expand_between(start, end, spec)
}

fn expand_between(start: IpAddr, end: IpAddr, spec: &str) -> Result<Vec<IpAddr>, TargetError> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            let s = u32::from(s);
            let e = u32::from(e);
            if s > e {
                return Err(TargetError::Invalid(spec.into(), "range start is greater than end".into()));
            }
            let count = (e - s + 1) as u64;
            if count > MAX_TARGETS {
                return Err(TargetError::TooLarge(spec.into(), count, MAX_TARGETS));
            }
            Ok((s..=e).map(|x| IpAddr::V4(Ipv4Addr::from(x))).collect())
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            let s = u128::from(s);
            let e = u128::from(e);
            if s > e {
                return Err(TargetError::Invalid(spec.into(), "range start is greater than end".into()));
            }
            let count = (e - s + 1) as u64;
            if count > MAX_TARGETS {
                return Err(TargetError::TooLarge(spec.into(), count, MAX_TARGETS));
            }
            Ok((s..=e).map(|x| IpAddr::V6(Ipv6Addr::from(x))).collect())
        }
        _ => Err(TargetError::Invalid(spec.into(), "cannot mix IPv4 and IPv6 in a range".into())),
    }
}

async fn expand_one(raw: &str) -> Result<Vec<ResolvedHost>, TargetError> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return Ok(Vec::new());
    }

    // @file: one target per line, supports comments and blank lines.
    if let Some(path) = raw.strip_prefix('@') {
        let text = std::fs::read_to_string(path)
            .map_err(|e| TargetError::ReadFile(path.into(), e.to_string()))?;
        let mut out = Vec::new();
        for line in text.lines() {
            // Recursive async fn must be boxed to keep the future sized.
            out.extend(Box::pin(expand_one(line)).await?);
        }
        return Ok(out);
    }

    // CIDR block.
    if raw.contains('/') {
        let ips = parse_cidr(raw)?;
        return Ok(ips.into_iter().map(|ip| ResolvedHost { ip, hostname: None }).collect());
    }

    // IP range — but only when the left side parses as an IP, so hostnames
    // containing '-' (e.g. "my-host.com") still resolve normally.
    if raw.contains('-') {
        let left = raw.split_once('-').map(|(l, _)| l.trim()).unwrap_or(raw);
        if left.parse::<IpAddr>().is_ok() {
            let ips = parse_ip_range(raw)?;
            return Ok(ips.into_iter().map(|ip| ResolvedHost { ip, hostname: None }).collect());
        }
    }

    // Bare IP address.
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(vec![ResolvedHost { ip, hostname: None }]);
    }

    // Hostname: resolve to all addresses.
    let mut out = Vec::new();
    let addrs = tokio::net::lookup_host((raw, 0))
        .await
        .map_err(|_| TargetError::Resolve(raw.into()))?;
    for addr in addrs {
        out.push(ResolvedHost { ip: addr.ip(), hostname: Some(raw.to_string()) });
    }
    if out.is_empty() {
        return Err(TargetError::Resolve(raw.into()));
    }
    Ok(out)
}

/// Expand every raw target, resolving hostnames, then return the list of
/// hosts deduplicated by IP (entries that carry a hostname win) and sorted.
pub async fn expand_targets(raw: &[String]) -> Result<Vec<ResolvedHost>, TargetError> {
    let mut all: Vec<ResolvedHost> = Vec::new();
    for r in raw {
        all.extend(expand_one(r).await?);
    }
    // Sort by IP; for equal IPs put hostname-bearing entries first so the
    // `dedup_by` below keeps the friendlier one.
    all.sort_by(|a, b| {
        a.ip
            .cmp(&b.ip)
            .then_with(|| b.hostname.is_some().cmp(&a.hostname.is_some()))
    });
    all.dedup_by(|a, b| a.ip == b.ip);
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parses_single_ip() {
        assert_eq!(parse_cidr("192.168.1.5/32").unwrap(), vec![v4(192, 168, 1, 5)]);
    }

    #[test]
    fn expands_cidr() {
        // /30 hosts() excludes network and broadcast -> .1 and .2
        let ips = parse_cidr("192.168.1.0/30").unwrap();
        assert_eq!(ips, vec![v4(192, 168, 1, 1), v4(192, 168, 1, 2)]);
    }

    #[test]
    fn expands_slash_31_fully() {
        assert_eq!(
            parse_cidr("192.168.1.2/31").unwrap(),
            vec![v4(192, 168, 1, 2), v4(192, 168, 1, 3)]
        );
    }

    #[test]
    fn rejects_huge_cidr() {
        assert!(parse_cidr("10.0.0.0/8").is_err());
    }

    #[test]
    fn expands_ip_range() {
        let ips = parse_ip_range("192.168.1.5-192.168.1.7").unwrap();
        assert_eq!(
            ips,
            vec![v4(192, 168, 1, 5), v4(192, 168, 1, 6), v4(192, 168, 1, 7)]
        );
    }

    #[test]
    fn expands_octet_range() {
        let ips = parse_ip_range("192.168.1.5-7").unwrap();
        assert_eq!(
            ips,
            vec![v4(192, 168, 1, 5), v4(192, 168, 1, 6), v4(192, 168, 1, 7)]
        );
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_ip_range("192.168.1.9-192.168.1.5").is_err());
    }

    #[test]
    fn expands_ipv6_range() {
        let start: IpAddr = "fe80::1".parse().unwrap();
        let end: IpAddr = "fe80::3".parse().unwrap();
        let ips = expand_between(start, end, "fe80::1-fe80::3").unwrap();
        assert_eq!(ips.len(), 3);
    }

    #[tokio::test]
    async fn expands_and_dedupes_targets() {
        let targets = expand_targets(&[
            "127.0.0.1".to_string(),
            "192.168.1.5-192.168.1.6".to_string(),
            "127.0.0.1".to_string(),
        ])
        .await
        .unwrap();
        assert_eq!(
            targets.iter().map(|h| h.ip).collect::<Vec<_>>(),
            vec![v4(127, 0, 0, 1), v4(192, 168, 1, 5), v4(192, 168, 1, 6)]
        );
    }

    #[tokio::test]
    async fn resolves_hostname() {
        let targets = expand_targets(&["localhost".to_string()]).await.unwrap();
        assert!(!targets.is_empty());
        assert!(targets.iter().any(|h| h.ip.is_loopback()));
        assert_eq!(targets[0].hostname.as_deref(), Some("localhost"));
    }

    #[tokio::test]
    async fn dedupes_by_ip_keeping_hostname() {
        // "localhost" (resolves to 127.0.0.1 and ::1) and "127.0.0.1" should
        // collapse into a single IPv4 entry that carries the hostname.
        let targets =
            expand_targets(&["localhost".to_string(), "127.0.0.1".to_string()]).await.unwrap();
        let v4_loopbacks: Vec<_> = targets
            .iter()
            .filter(|h| h.ip.is_loopback() && h.ip.is_ipv4())
            .collect();
        assert_eq!(v4_loopbacks.len(), 1);
        assert_eq!(v4_loopbacks[0].hostname.as_deref(), Some("localhost"));
        // The IPv6 loopback should still be present (distinct IP).
        assert!(targets.iter().any(|h| h.ip.is_loopback() && h.ip.is_ipv6()));
    }

    #[tokio::test]
    async fn rejects_unresolvable_hostname() {
        assert!(expand_targets(&["this-host-does-not-exist.invalid".to_string()])
            .await
            .is_err());
    }
}
