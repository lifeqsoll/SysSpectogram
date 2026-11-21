//! Helpers for `/proc/net/tcp` address fields (hex-encoded).

/// Parse `local_address` / `rem_address` from procfs (`IP:PORT` as little-endian IP, big-endian port hex).
pub fn parse_tcp_hex_addr(field: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    if ip_hex.len() != 8 {
        return None;
    }
    let a = u8::from_str_radix(&ip_hex[6..8], 16).ok()?;
    let b = u8::from_str_radix(&ip_hex[4..6], 16).ok()?;
    let c = u8::from_str_radix(&ip_hex[2..4], 16).ok()?;
    let d = u8::from_str_radix(&ip_hex[0..2], 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((format!("{a}.{b}.{c}.{d}"), port))
}

/// Split a `/proc/net/tcp` data line into tokens (skips header).
pub fn split_tcp_line(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loopback_ssh() {
        let (ip, port) = parse_tcp_hex_addr("0100007F:0016").unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_public_example() {
        let (ip, port) = parse_tcp_hex_addr("6400A8C0:01BB").unwrap();
        assert_eq!(ip, "192.168.0.100");
        assert_eq!(port, 443);
    }

    #[test]
    fn invalid_hex_returns_none() {
        assert!(parse_tcp_hex_addr("not-valid").is_none());
        assert!(parse_tcp_hex_addr("0100007F").is_none());
    }
}