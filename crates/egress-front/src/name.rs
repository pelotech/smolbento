//! The name a flow's first bytes ask for: TLS SNI, or an HTTP request's `Host:`.

use smolvm_protocol::sni::{Peek, peek_client_hello};

/// The host name in a flow's first bytes: the SNI of a TLS ClientHello, else the `Host:` header of an
/// HTTP request (port stripped). Lowercased, without a trailing dot. `None` when there is neither.
pub fn flow_name(first: &[u8]) -> Option<String> {
    let name = match peek_client_hello(first) {
        Peek::ServerName(sni) => sni,
        _ => http_host(first)?,
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

/// The `Host:` header of an HTTP/1 request, without its port. Only whole lines count, so a header cut
/// off by the first-bytes read is not taken for a shorter name.
fn http_host(first: &[u8]) -> Option<String> {
    // Stop at the headers' end, so a body that isn't UTF-8 doesn't hide them.
    let end = match first.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(end) => end,
        None => first.windows(2).rposition(|w| w == b"\r\n")?,
    };
    let head = std::str::from_utf8(&first[..end]).ok()?;
    let mut lines = head.split("\r\n");
    if !lines.next()?.contains(" HTTP/1.") {
        return None;
    }
    let value = lines.take_while(|l| !l.is_empty()).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("host").then_some(v.trim())
    })?;
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

    #[test]
    fn flows_without_a_name() {
        assert_eq!(flow_name(b""), None);
        assert_eq!(flow_name(b"SSH-2.0-x\r\n"), None);
        assert_eq!(flow_name(b"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n"), None);
        assert_eq!(flow_name(&client_hello(None)), None);
        // A Host: header cut off mid-value is not a name.
        assert_eq!(flow_name(b"GET / HTTP/1.1\r\nHost: exa"), None);
        // Not an HTTP request.
        assert_eq!(flow_name(b"Host: example.com\r\n\r\n"), None);
    }
}
