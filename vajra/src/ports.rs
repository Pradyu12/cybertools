//! Port specification parsing and the built-in top-ports list.
//!
//! Accepted syntax:
//! - a single port: `80`
//! - a range: `1-1000`
//! - a comma-separated mix: `80,443,8000-8010`
//! - the top list: `top-100`, `top-1000` (clamped to the built-in list)

use std::collections::BTreeSet;

use thiserror::Error;

/// Errors produced while parsing port specifications.
#[derive(Debug, Error)]
pub enum PortError {
    #[error("invalid port or range `{0}`")]
    Invalid(String),
    #[error("empty port specification")]
    Empty,
    #[error("port range `{0}` is invalid: lower bound is greater than upper bound")]
    Reversed(String),
    #[error("port 0 is not a valid TCP port")]
    Zero,
}

/// Built-in list of the most commonly used TCP ports, roughly ordered by how
/// frequently they appear open on the internet. `top-N` specs clamp to this
/// list.
pub const TOP_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 53, 3389, 8080, 110, 143, 445, 139, 23, 3306, 5432, 6379, 27017, 5900,
    1080, 8443, 1433, 1521, 8000, 8888, 9200, 11211, 161, 162, 179, 993, 995, 587, 465, 631, 514,
    512, 513, 515, 548, 554, 623, 636, 646, 749, 873, 902, 904, 981, 990, 992, 1000, 1001, 1010,
    1025, 1026, 1027, 1028, 1030, 1081, 1119, 1131, 1194, 1214, 1220, 1311, 1337, 1434, 1443,
    1500, 1524, 1723, 1812, 1813, 1900, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
    2222, 2375, 2376, 2424, 2480, 2525, 3000, 3128, 3268, 3269, 3307, 3388, 3460, 3542, 3689,
    3690, 4000, 4040, 4443, 4500, 4567, 4848, 5000, 5001, 5003, 5060, 5061, 5222, 5223, 5269,
    5353, 5357, 5433, 5555, 5601, 5672, 5800, 5901, 5984, 5985, 5986, 6000, 6001, 6002, 6060,
    6443, 6667, 7001, 7002, 7070, 7443, 7474, 7547, 7777, 8008, 8009, 8010, 8060, 8081, 8082,
    8083, 8088, 8090, 8123, 8161, 8200, 8222, 8333, 8500, 8600, 8880, 8899, 9000, 9001, 9002,
    9042, 9043, 9090, 9092, 9100, 9300, 9443, 9600, 9999, 10000, 10080, 10250, 11443, 12345,
    15672, 16379, 17000, 18080, 20000, 22222, 25565, 27018, 28017, 32400, 32768, 33389, 33899,
    37777, 49152, 50000, 50030, 50070, 54321, 61616, 64738, 65535,
];

/// Built-in list of UDP ports probed by the `--udp` scanner (see `udp.rs`).
pub const TOP_UDP_PORTS: &[u16] = &[
    7, 9, 13, 17, 19, 37, 53, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 623,
    631, 1434, 1701, 1900, 2049, 3074, 3702, 4500, 5000, 5060, 5061, 5353, 5355, 5678, 6000,
    6001, 7777, 9999, 10000, 11211, 1194, 12345, 20031, 31337, 32768, 51820,
];

/// Parse a port specification against the built-in TCP top-ports list.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, PortError> {
    parse_ports_with(spec, TOP_PORTS)
}

/// Parse a port specification into a sorted, de-duplicated list of ports,
/// using `top` as the base list for `top-N` specs.
pub fn parse_ports_with(spec: &str, top: &[u16]) -> Result<Vec<u16>, PortError> {
    let mut set = BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(n) = part.strip_prefix("top-") {
            let n: usize = n
                .trim()
                .parse()
                .map_err(|_| PortError::Invalid(part.to_string()))?;
            set.extend(top.iter().take(n).copied());
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u16 = lo
                .trim()
                .parse()
                .map_err(|_| PortError::Invalid(part.to_string()))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .map_err(|_| PortError::Invalid(part.to_string()))?;
            if lo == 0 || hi == 0 {
                return Err(PortError::Zero);
            }
            if lo > hi {
                return Err(PortError::Reversed(part.to_string()));
            }
            set.extend(lo..=hi);
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| PortError::Invalid(part.to_string()))?;
            if p == 0 {
                return Err(PortError::Zero);
            }
            set.insert(p);
        }
    }
    if set.is_empty() {
        return Err(PortError::Empty);
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn parses_list() {
        assert_eq!(parse_ports("80,443,8080").unwrap(), vec![80, 443, 8080]);
    }

    #[test]
    fn parses_range() {
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn parses_mixed_and_dedupes() {
        assert_eq!(
            parse_ports("8080-8082,80,8081").unwrap(),
            vec![80, 8080, 8081, 8082]
        );
    }

    #[test]
    fn parses_top_n() {
        // parse_ports returns sorted ports, so compare against the sorted prefix.
        let mut expected: Vec<u16> = TOP_PORTS[..5].to_vec();
        expected.sort_unstable();
        assert_eq!(parse_ports("top-5").unwrap(), expected);
    }

    #[test]
    fn clamps_top_n() {
        let mut expected = TOP_PORTS.to_vec();
        expected.sort_unstable();
        assert_eq!(parse_ports("top-999999").unwrap(), expected);
    }

    #[test]
    fn handles_full_range() {
        let ports = parse_ports("1-65535").unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }

    #[test]
    fn rejects_zero() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("0-100").is_err());
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_ports("100-1").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("80,xyz").is_err());
        assert!(parse_ports("").is_err());
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn parses_against_custom_top_list() {
        let ports = parse_ports_with("top-3", TOP_UDP_PORTS).unwrap();
        assert_eq!(ports, vec![7, 9, 13]);
    }

    #[test]
    fn udp_spec_mixes_explicit_and_top() {
        let ports = parse_ports_with("53,161,top-2", TOP_UDP_PORTS).unwrap();
        assert_eq!(ports, vec![7, 9, 53, 161]);
    }
}
