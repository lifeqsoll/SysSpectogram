//! Auth.log / journal-style SSH fail line parsing (parity with Python perimeter.auth).

/// Extract peer IP from a Failed/Invalid sshd line (last `from <ip> port` when unique).
pub fn parse_auth_fail_ip(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if !(lower.contains("failed password")
        || lower.contains("invalid user")
        || lower.contains("authentication failure"))
    {
        return None;
    }
    let mut ips = Vec::new();
    let bytes = line.as_bytes();
    let needle = b" from ";
    let mut i = 0;
    while i + needle.len() < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let start = i + needle.len();
            let mut end = start;
            while end < bytes.len() {
                let c = bytes[end] as char;
                if c.is_ascii_alphanumeric() || c == '.' || c == ':' {
                    end += 1;
                } else {
                    break;
                }
            }
            if end > start {
                let cand = &line[start..end];
                if cand.contains('.') || cand.contains(':') {
                    ips.push(cand.to_string());
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    if ips.is_empty() {
        return None;
    }
    // Prefer the last IP (sshd peer) when multiple `from` tokens exist.
    Some(ips[ips.len() - 1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_password() {
        let ip = parse_auth_fail_ip(
            "Failed password for root from 203.0.113.9 port 22 ssh2",
        );
        assert_eq!(ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn prefers_trailing_peer_on_injection() {
        let ip = parse_auth_fail_ip(
            "Invalid user x from 0.0.0.0/0 from 198.51.100.7 port 22 ssh2",
        );
        // Slash stops the first token; second from wins.
        assert_eq!(ip.as_deref(), Some("198.51.100.7"));
    }
}
