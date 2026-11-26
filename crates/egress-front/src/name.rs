//! The name a flow's first bytes ask for: TLS SNI, or an HTTP request's `Host:`.

use smolvm_protocol::sni::{Peek, peek_client_hello};

use crate::relay::FlowKind;

/// What a flow's first bytes are and the host name they ask for, from one parse: a TLS ClientHello
/// with an SNI is `Tls` with that name; anything else starting with a TLS handshake record is `Tls`
/// with no name; an HTTP/1 request is `Http` with its one `Host:` (port stripped), if any; anything
/// else is `Other` with no name. A name is lowercased, without a trailing dot.
pub(crate) fn flow_id(first: &[u8]) -> (Option<String>, FlowKind) {
    let (name, kind) = match peek_client_hello(first) {
        Peek::ServerName(sni) => (Some(sni), FlowKind::Tls),
        // A handshake record never carries an HTTP name: TLS that hides its SNI is nameless TLS.
        _ if first.first() == Some(&0x16) => (None, FlowKind::Tls),
        _ if request_line(first) => (http_host(first), FlowKind::Http),
        _ => (None, FlowKind::Other),
    };
    let name = name
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .filter(|n| !n.is_empty());
    (name, kind)
}

/// The whole HTTP/1 lines of `first`, each ended by `\n` with an optional `\r`, from the request line
/// on: what follows the last `\n` may be cut off by the first-bytes read, so it isn't a line, and
/// servers skip empty lines before the request line (RFC 9112 section 2.2).
fn lines(first: &[u8]) -> impl Iterator<Item = &[u8]> {
    let whole = first
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(&[][..], |end| &first[..end]);
    whole
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .skip_while(|l| l.is_empty())
}

/// Whether `first` starts with a whole HTTP/1 request line.
fn request_line(first: &[u8]) -> bool {
    lines(first)
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .is_some_and(|line| line.contains(" HTTP/1."))
}

/// The `Host:` header of an HTTP/1 request, without its port; none when there are several, as the
/// server may read another one than the rules would.
fn http_host(first: &[u8]) -> Option<String> {
    // Stop at the headers' end, so a body that isn't UTF-8 doesn't hide them.
    let head = lines(first)
        .skip(1)
        .take_while(|l| !l.is_empty())
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let mut hosts = head.iter().filter_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("host").then_some(v.trim())
    });
    let value = hosts.next()?;
    if hosts.next().is_some() {
        return None;
    }
    let host = match value.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.0,
        None => value.split_once(':').map_or(value, |(h, _)| h),
    };
    Some(host.to_owned())
}

/// A minimal TLS 1.2-style ClientHello record carrying `sni` (smolvm-protocol's `sni` test builder).
#[cfg(test)]
pub(crate) fn client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    let mut exts = Vec::new();
    if let Some(name) = sni {
        let mut entry = vec![0x00];
        entry.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut list = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&list);
    }
    exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // an unrelated extension
    body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&exts);
    let mut hs = vec![0x01];
    hs.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_name(first: &[u8]) -> Option<String> {
        flow_id(first).0
    }

    #[test]
    fn flow_name_reads_sni() {
        assert_eq!(
            flow_name(&client_hello(Some("API.Example.com."))).as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn flow_name_reads_the_host_header() {
        assert_eq!(
            flow_name(b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            flow_name(b"POST /x HTTP/1.1\r\nUser-Agent: t\r\nhost:  api.example.com.\r\n\r\nbody")
                .as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            flow_name(b"POST / HTTP/1.1\r\nHost: a.example\r\n\r\n\xff\r\n").as_deref(),
            Some("a.example")
        );
        assert_eq!(
            flow_name(b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n").as_deref(),
            Some("::1")
        );
    }

    const FAKE_TLS: &[u8] = b"\x16\x03\x01\x00\x01X HTTP/1.1\r\nHost: ruled\r\n\r\n";

    #[test]
    fn a_fake_tls_header_with_a_host_header_is_nameless_tls() {
        assert_eq!(flow_id(FAKE_TLS), (None, FlowKind::Tls));
    }

    #[test]
    fn tls_without_sni_reports_tls() {
        assert_eq!(flow_id(&client_hello(None)), (None, FlowKind::Tls));
        assert_eq!(
            flow_id(&client_hello(Some("a.example"))[..8]),
            (None, FlowKind::Tls)
        );
        assert_eq!(
            flow_id(&client_hello(Some("A.example"))),
            (Some("a.example".into()), FlowKind::Tls)
        );
    }

    #[test]
    fn an_http_request_is_http() {
        assert_eq!(
            flow_id(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"),
            (Some("a.example".into()), FlowKind::Http)
        );
        // No `Host:`: still HTTP, with no name.
        assert_eq!(flow_id(b"GET / HTTP/1.0\r\n\r\n"), (None, FlowKind::Http));
        assert_eq!(flow_id(b"GET / HTTP/1.1"), (None, FlowKind::Other));
        assert_eq!(flow_id(b"SSH-2.0-x\r\n"), (None, FlowKind::Other));
        assert_eq!(flow_id(b""), (None, FlowKind::Other));
    }

    #[test]
    fn bare_lf_http_reads_host() {
        assert_eq!(
            flow_id(b"GET / HTTP/1.1\nHost: blocked.com\n\n"),
            (Some("blocked.com".into()), FlowKind::Http)
        );
    }

    #[test]
    fn empty_lines_before_the_request_line_are_skipped() {
        for first in [
            &b"\r\nGET / HTTP/1.1\r\nHost: gist.github.com\r\n\r\n"[..],
            b"\nGET / HTTP/1.1\nHost: gist.github.com\n\n",
            b"\r\n\n\r\nGET / HTTP/1.1\r\nHost: gist.github.com\r\n\r\n",
        ] {
            assert_eq!(
                flow_id(first),
                (Some("gist.github.com".into()), FlowKind::Http),
                "{first:?}"
            );
        }
        assert_eq!(flow_id(b"\r\n\r\n"), (None, FlowKind::Other));
    }

    #[test]
    fn two_host_lines_give_no_name() {
        assert_eq!(
            flow_id(b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n"),
            (None, FlowKind::Http)
        );
    }

    #[test]
    fn flows_without_a_name() {
        assert_eq!(flow_name(b"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n"), None);
        // A Host: header cut off mid-value is not a name.
        assert_eq!(flow_name(b"GET / HTTP/1.1\r\nHost: exa"), None);
        // Not an HTTP request.
        assert_eq!(flow_name(b"Host: example.com\r\n\r\n"), None);
    }
}
