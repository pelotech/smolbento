//! Host keys for `authenticate`, from the user's `known_hosts` file on the host (never from
//! anything the sandbox presents). Only what a literal `authenticate` host can mean is trusted.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};
use ssh_key::public::KeyData;

/// The keys `text` (a `known_hosts` file) lists for `host`, on the default port:
/// - plain names in a comma list and hashed `|1|salt|hash` names match `host` exactly;
/// - a `@revoked` key is dropped, whatever name it was listed under;
/// - `@cert-authority` lines, wildcard (`*`, `?`) patterns, lines with a negated (`!`) pattern
///   and `[host]:port` names never match;
/// - a line that doesn't parse is skipped.
pub fn host_keys(text: &str, host: &str) -> Vec<KeyData> {
    let mut trusted = Vec::new();
    let mut revoked = Vec::new();
    for entry in KnownHosts::new(text).flatten() {
        let key = entry.public_key().key_data();
        match entry.marker() {
            Some(Marker::Revoked) => revoked.push(key.clone()),
            Some(Marker::CertAuthority) => {}
            None => {
                if names(entry.host_patterns(), host) {
                    trusted.push(key.clone());
                }
            }
        }
    }
    trusted.retain(|k| !revoked.contains(k));
    trusted
}

fn names(patterns: &HostPatterns, host: &str) -> bool {
    match patterns {
        // A negated pattern excludes hosts in OpenSSH's rules; never trust such a line.
        HostPatterns::Patterns(list) => {
            !list.iter().any(|p| p.starts_with('!')) && list.iter().any(|p| p == host && literal(p))
        }
        HostPatterns::HashedName { salt, hash } => Hmac::<Sha1>::new_from_slice(salt)
            .map(|mut mac| {
                mac.update(host.as_bytes());
                mac.verify_slice(hash).is_ok()
            })
            .unwrap_or(false),
    }
}

/// A plain name: no wildcard, negation or `[host]:port` form.
fn literal(p: &str) -> bool {
    !p.is_empty() && !p.contains(['*', '?', '!', '[', ']'])
}

#[cfg(test)]
pub(crate) mod testkeys {
    use ssh_key::PrivateKey;
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    use ssh_key::public::KeyData;

    /// A deterministic ed25519 host or user key.
    pub fn key(n: u8) -> PrivateKey {
        PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[n; 32])),
            "",
        )
        .unwrap()
    }

    pub fn data(n: u8) -> KeyData {
        key(n).public_key().key_data().clone()
    }

    /// `key(n)` as a `known_hosts` key field.
    pub fn line(n: u8) -> String {
        key(n).public_key().to_openssh().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testkeys::{data, line};
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    fn hashed(host: &str, key: u8) -> String {
        let salt = [7u8; 20];
        let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
        mac.update(host.as_bytes());
        let hash = mac.finalize().into_bytes();
        format!(
            "|1|{}|{} {}",
            STANDARD.encode(salt),
            STANDARD.encode(hash),
            line(key)
        )
    }

    #[test]
    fn plain_names_match_exactly() {
        let t = format!(
            "# a comment\n\ngithub.com,140.82.1.1 {}\nother.org {}\ngithub.com {} trailing comment\n",
            line(1),
            line(2),
            line(3)
        );
        assert_eq!(host_keys(&t, "github.com"), [data(1), data(3)]);
        assert_eq!(host_keys(&t, "other.org"), [data(2)]);
        for h in [
            "hub.com",
            "xgithub.com",
            "github.com.evil",
            "140.82.1.1x",
            "",
        ] {
            assert!(host_keys(&t, h).is_empty(), "{h}");
        }
        assert_eq!(host_keys(&t, "140.82.1.1"), [data(1)]);
    }

    #[test]
    fn hashed_names_match_by_hmac() {
        let t = format!("{}\n{}\n", hashed("github.com", 1), hashed("gitlab.com", 2));
        assert_eq!(host_keys(&t, "github.com"), [data(1)]);
        assert_eq!(host_keys(&t, "gitlab.com"), [data(2)]);
        assert!(host_keys(&t, "example.com").is_empty());
        assert!(host_keys(&t, "GITHUB.COM").is_empty());
    }

    #[test]
    fn revoked_keys_are_dropped_for_every_name() {
        let t = format!(
            "a.com {}\nb.com {}\n@revoked * {}\n",
            line(1),
            line(2),
            line(1)
        );
        assert!(host_keys(&t, "a.com").is_empty());
        assert_eq!(host_keys(&t, "b.com"), [data(2)]);
        // Revoked under another name, or hashed.
        let t = format!("a.com {}\n@revoked other.org {}\n", line(1), line(1));
        assert!(host_keys(&t, "a.com").is_empty());
        let t = format!("a.com {}\n@revoked {}\n", line(1), hashed("x.org", 1));
        assert!(host_keys(&t, "a.com").is_empty());
    }

    #[test]
    fn cas_wildcards_negation_and_ports_never_match() {
        let t = format!(
            "@cert-authority a.com {}\n*.a.com {}\n* {}\n?.a.com {}\n!a.com,a.com {}\n[a.com]:2222 {}\n[a.com] {}\n",
            line(1),
            line(2),
            line(3),
            line(4),
            line(5),
            line(6),
            line(7)
        );
        for h in [
            "a.com",
            "x.a.com",
            "b.a.com",
            "*.a.com",
            "*",
            "[a.com]:2222",
        ] {
            assert!(host_keys(&t, h).is_empty(), "{h}");
        }
    }

    #[test]
    fn garbage_lines_are_skipped() {
        let t = format!("nonsense\na.com notakey AAAA\na.com {}\n", line(1));
        assert_eq!(host_keys(&t, "a.com"), [data(1)]);
        assert!(host_keys("", "a.com").is_empty());
    }
}
