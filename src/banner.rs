//! Service detection: banner grabbing and heuristic service identification.
//!
//! For every open port we connect again and, depending on the port, either
//! wait for a greeting (SSH, FTP, SMTP, databases), send an HTTP request,
//! send a TLS ClientHello, or nudge the service with a bare newline. Whatever
//! comes back is sanitised, fingerprinted, and matched against a small
//! signature table with a port-based fallback.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// An open port enriched with service-detection results.
#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

impl OpenPort {
    /// Create a port entry with the port-based service fallback only.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            protocol: "tcp".into(),
            state: "open".into(),
            service: service_for_port(port),
            version: None,
            banner: None,
        }
    }
}

/// A minimal, valid TLS 1.2 ClientHello. Servers that speak TLS will answer
/// with a ServerHello; plaintext HTTP servers will answer with a 400.
const TLS_CLIENT_HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0x31, // record header, length 49
    0x01, 0x00, 0x00, 0x2d, // handshake header, length 45
    0x03, 0x03, // TLS 1.2
    // 32 bytes of client random
    0x42, 0x9a, 0x1f, 0x2c, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0d, 0x0e, 0x0f, 0x10,
    0x00, // no session id
    0x00, 0x04, // two cipher suites
    0xc0, 0x2f, 0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA variants
    0x01, // one compression method
    0x00, // null compression
    0x00, 0x00, // no extensions
];

const MAX_BANNER: usize = 1024;

/// Ports that typically expect the client to speak first over TLS.
fn is_tls_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 636 | 853 | 989 | 990 | 992 | 993 | 994 | 995 | 3269 | 4443 | 8443 | 9443 | 11443
    )
}

/// Read whatever the server sends until silence, EOF, the budget, or the
/// banner cap is reached.
async fn read_banner(stream: &mut TcpStream, budget: Duration) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut out = Vec::with_capacity(256);
    let mut buf = [0u8; 4096];
    loop {
        if out.len() >= MAX_BANNER {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wait = remaining.min(Duration::from_millis(250));
        match tokio::time::timeout(wait, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            _ => break, // silence or error
        }
    }
    out
}

/// Probe a single open port and return its enriched entry.
pub async fn grab_banner(ip: IpAddr, port: u16, connect_timeout: Duration) -> (IpAddr, OpenPort) {
    let mut info = OpenPort::new(port);
    let addr = SocketAddr::new(ip, port);
    let mut stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return (ip, info),
    };
    let _ = stream.set_nodelay(true);

    let tls_first = is_tls_port(port);
    let mut banner: Vec<u8>;

    if tls_first {
        let _ = stream.write_all(TLS_CLIENT_HELLO).await;
        banner = read_banner(&mut stream, Duration::from_millis(900)).await;
        if banner.is_empty() {
            let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n").await;
            banner = read_banner(&mut stream, Duration::from_millis(600)).await;
        }
    } else {
        // Many services greet immediately: SSH, FTP, SMTP, databases, ...
        banner = read_banner(&mut stream, Duration::from_millis(900)).await;
        if banner.is_empty() {
            let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n").await;
            banner = read_banner(&mut stream, Duration::from_millis(700)).await;
        }
        if banner.is_empty() {
            let _ = stream.write_all(TLS_CLIENT_HELLO).await;
            banner = read_banner(&mut stream, Duration::from_millis(700)).await;
        }
        if banner.is_empty() {
            let _ = stream.write_all(b"\r\n").await;
            banner = read_banner(&mut stream, Duration::from_millis(400)).await;
        }
    }

    let text = sanitize(&banner);
    if !text.is_empty() {
        let (service, version) = guess(port, &text);
        info.service = Some(service);
        info.version = version;
        info.banner = Some(text);
    }
    (ip, info)
}

/// Convert raw banner bytes into a printable, single-line string.
fn sanitize(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if b == b'\r' {
            continue;
        }
        if b == b'\n' {
            s.push('\\');
            s.push('n');
        } else if (0x20..=0x7e).contains(&b) {
            s.push(b as char);
        } else if b == b'\t' {
            s.push(' ');
        } else {
            s.push('·');
        }
    }
    // Collapse whitespace runs.
    let mut out = String::new();
    let mut prev_space = false;
    for c in s.chars() {
        if c == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    let mut out = out.trim().to_string();
    let count = out.chars().count();
    if count > 300 {
        out = out.chars().take(300).collect();
        out.push('…');
    }
    out
}

/// Best-effort version extraction: the first `X.Y`-style token in the banner.
fn extract_version(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            let dots = tok.matches('.').count();
            if (1..=3).contains(&dots)
                && tok.len() <= 12
                && !tok.starts_with('.')
                && !tok.ends_with('.')
            {
                return Some(tok);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Fingerprint the service from banner content, falling back to the port.
fn guess(port: u16, text: &str) -> (String, Option<String>) {
    let lower = text.to_ascii_lowercase();
    let service = if lower.contains("ssh-2.0") || lower.contains("ssh-1.99") || lower.contains("openssh") {
        "ssh"
    } else if lower.contains("http/1.")
        || lower.contains("http/2")
        || lower.contains("microsoft-httpapi")
        || lower.contains("nginx")
        || lower.contains("apache")
    {
        "http"
    } else if lower.contains("smtp") || lower.contains("esmtp") {
        "smtp"
    } else if lower.contains("ftp") {
        "ftp"
    } else if lower.contains("mariadb") {
        "mariadb"
    } else if lower.contains("mysql") {
        "mysql"
    } else if lower.contains("postgresql") || lower.contains("postgres") {
        "postgresql"
    } else if lower.contains("redis") {
        "redis"
    } else if lower.contains("mongodb") {
        "mongodb"
    } else if lower.contains("memcached") {
        "memcached"
    } else if lower.contains("rfb") || lower.contains("vnc") {
        "vnc"
    } else if lower.contains("telnet") {
        "telnet"
    } else if lower.contains("pop3") {
        "pop3"
    } else if lower.contains("imap") {
        "imap"
    } else if lower.contains("ldap") {
        "ldap"
    } else if lower.contains("kerberos") {
        "kerberos"
    } else if lower.contains("docker") {
        "docker"
    } else if lower.contains("sip/2") {
        "sip"
    } else if lower.contains("msrpc") || lower.contains("dcom") {
        "msrpc"
    } else if lower.contains("samba") || lower.contains("smb") {
        "smb"
    } else if lower.contains("openvpn") {
        "openvpn"
    } else if lower.contains("rdp") {
        "rdp"
    } else {
        "unknown"
    };
    let service = if service == "unknown" {
        service_for_port(port).unwrap_or_else(|| "unknown".to_string())
    } else {
        service.to_string()
    };
    (service, extract_version(text))
}

/// IANA-ish port → service fallback table.
pub fn service_for_port(port: u16) -> Option<String> {
    let s = match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67 | 68 => "dhcp",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137..=139 => "netbios",
        143 => "imap",
        161 | 162 => "snmp",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        464 => "kpasswd",
        465 => "smtps",
        514 => "syslog",
        515 => "printer",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        990 => "ftps",
        992 => "telnets",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "ms-sql",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 | 2376 => "docker",
        3000 => "http-alt",
        3128 => "squid",
        3268 => "ldap",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        4443 => "https-alt",
        5000 => "upnp",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        5985 => "wsman",
        5986 => "wsmans",
        6379 => "redis",
        6443 => "kubernetes",
        7001 => "weblogic",
        8000 => "http-alt",
        8008..=8009 => "http-alt",
        8080 => "http-proxy",
        8081 | 8082 | 8088 | 8090 => "http-alt",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "cslistener",
        9090 => "http-alt",
        9092 => "kafka",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        9418 => "git",
        9443 => "https-alt",
        9999 => "http-alt",
        10000 => "webmin",
        11211 => "memcached",
        15672 => "rabbitmq",
        16379 => "redis",
        27017 => "mongod",
        50000 => "http-alt",
        61616 => "activemq",
        _ => return None,
    };
    Some(s.into())
}
