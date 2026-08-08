//! Pure-Rust PMKID cracking (the wifite offline attack, no GPU needed).
//!
//! PMKID recovery, per the 2018 research by Jens Steube (hashcat):
//!   1. PMK   = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096 iterations, 32 bytes)
//!   2. PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || Client_MAC)[0..16]
//!
//! This module dictionary-cracks a captured PMKID by trying every candidate
//! passphrase from a wordlist and comparing the first 16 bytes of the HMAC.

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use std::io::{BufRead, BufReader};

type HmacSha1 = Hmac<Sha1>;

const PMKID_LEN: usize = 16;
const PMK_LEN: usize = 32;
const PBKDF2_ITERS: u32 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum CrackError {
    #[error("invalid PMKID hex: {0}")]
    BadPmkid(String),
    #[error("invalid MAC address: {0}")]
    BadMac(String),
    #[error("wordlist error: {0}")]
    Io(#[from] std::io::Error),
}

/// The target of a crack: the captured hash plus the context needed to
/// verify candidates.
#[derive(Debug, Clone)]
pub struct PmkidTarget {
    pub pmkid: [u8; PMKID_LEN],
    pub ap_mac: [u8; 6],
    pub client_mac: [u8; 6],
    pub essid: String,
}

impl PmkidTarget {
    pub fn new(pmkid_hex: &str, ap_mac: &str, client_mac: &str, essid: &str) -> Result<Self, CrackError> {
        let pmkid = hex_to_bytes(pmkid_hex)
            .ok_or_else(|| CrackError::BadPmkid(pmkid_hex.to_string()))?;
        if pmkid.len() != PMKID_LEN {
            return Err(CrackError::BadPmkid(format!(
                "expected 32 hex chars, got {}",
                pmkid_hex.len()
            )));
        }
        Ok(PmkidTarget {
            pmkid: pmkid.try_into().unwrap(),
            ap_mac: parse_mac(ap_mac).ok_or_else(|| CrackError::BadMac(ap_mac.to_string()))?,
            client_mac: parse_mac(client_mac)
                .ok_or_else(|| CrackError::BadMac(client_mac.to_string()))?,
            essid: essid.to_string(),
        })
    }

    /// Compute the PMKID a given passphrase would produce for this target.
    pub fn compute_pmkid(&self, passphrase: &str) -> [u8; PMKID_LEN] {
        let mut pmk = [0u8; PMK_LEN];
        pbkdf2_hmac::<Sha1>(
            passphrase.as_bytes(),
            self.essid.as_bytes(),
            PBKDF2_ITERS,
            &mut pmk,
        );

        let mut ctx = HmacSha1::new_from_slice(&pmk).expect("hmac accepts any key length");
        ctx.update(b"PMK Name");
        ctx.update(&self.ap_mac);
        ctx.update(&self.client_mac);
        let tag = ctx.finalize().into_bytes();
        let mut out = [0u8; PMKID_LEN];
        out.copy_from_slice(&tag[..PMKID_LEN]);
        out
    }

    pub fn matches(&self, passphrase: &str) -> bool {
        self.compute_pmkid(passphrase) == self.pmkid
    }

    /// Externally-validated reference vector: this PMKID was computed with an
    /// independent Python implementation (hashlib + hmac) for passphrase
    /// "wifi-password-42" on essid "Airtel_venk_6990". A regression in the
    /// algorithm (iteration count, "PMK Name" prefix, byte order, truncation)
    /// fails this test even if our own code stays self-consistent.
    #[cfg(test)]
    pub fn reference_vector() -> PmkidTarget {
        PmkidTarget {
            pmkid: [
                0xa2, 0xc3, 0x0e, 0x23, 0xdf, 0x4e, 0x38, 0xdd,
                0xfc, 0x45, 0x74, 0x6a, 0xb3, 0xfd, 0xf6, 0xd4,
            ],
            ap_mac: [0x6c, 0x4f, 0x89, 0x95, 0x3c, 0xde],
            client_mac: [0x78, 0x2b, 0x46, 0x51, 0x8e, 0x48],
            essid: "Airtel_venk_6990".to_string(),
        }
    }

    /// Render the AP MAC as `aa:bb:cc:dd:ee:ff`.
    pub fn ap_mac_hex(&self) -> String {
        self.ap_mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Crack a PMKID against a wordlist file (one candidate per line). Returns
/// the first matching passphrase, or None. Progress is reported by bytes read
/// (single pass over the file).
pub fn crack_wordlist(
    target: &PmkidTarget,
    path: &str,
    on_progress: Option<&dyn Fn(usize, usize)>,
) -> Result<Option<String>, CrackError> {
    let file = std::fs::File::open(path)?;
    let total_bytes = file.metadata()?.len() as usize;
    let reader = BufReader::new(file);
    let mut bytes = 0usize;
    for line in reader.lines() {
        let line = line?;
        bytes += line.len() + 1; // +1 for the newline
        let pass = line.trim_end_matches('\r');
        if let Some(f) = on_progress {
            f(bytes, total_bytes);
        }
        if !pass.is_empty() && target.matches(pass) {
            return Ok(Some(pass.to_string()));
        }
    }
    Ok(None)
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex = s.replace([':', '-'], "");
    let bytes = hex_to_bytes(&hex)?;
    if bytes.len() != 6 {
        return None;
    }
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmkid_known_vector() {
        // Externally-verified reference: "wifi-password-42" on
        // "Airtel_venk_6990" (computed independently in Python).
        let t = PmkidTarget::reference_vector();
        assert!(t.matches("wifi-password-42"));
        assert!(!t.matches("wrong-password"));
        assert!(!t.matches("wifi-password-42 "));
    }

    #[test]
    fn pmkid_hex_encoding() {
        let t = PmkidTarget::reference_vector();
        let hex: String = t
            .pmkid
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, "a2c30e23df4e38ddfc45746ab3fdf6d4");
        // Rebuild from hex and verify it still matches.
        let rebuilt = PmkidTarget::new(
            &hex,
            "6c:4f:89:95:3c:de",
            "78:2b:46:51:8e:48",
            "Airtel_venk_6990",
        )
        .unwrap();
        assert!(rebuilt.matches("wifi-password-42"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(PmkidTarget::new("zz", "6c:4f:89:95:3c:de", "78:2b:46:51:8e:48", "x").is_err());
        assert!(PmkidTarget::new("abcd", "not-a-mac", "78:2b:46:51:8e:48", "x").is_err());
        assert!(PmkidTarget::new("abcd", "6c:4f:89:95:3c:de", "bad", "x").is_err());
    }

    #[test]
    fn crack_finds_password_from_wordlist() {
        let t = PmkidTarget::reference_vector();
        let dir = std::env::temp_dir();
        let path = dir.join("taranga_test_wordlist.txt");
        std::fs::write(&path, "password123\nletmein\nwifi-password-42\ntest\n").unwrap();
        let found = crack_wordlist(&t, path.to_str().unwrap(), None).unwrap();
        assert_eq!(found.as_deref(), Some("wifi-password-42"));
        std::fs::remove_file(&path).ok();
    }
}
