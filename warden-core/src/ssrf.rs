#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

#[derive(Debug, Clone, thiserror::Error)]
pub enum SsrfError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("URL must use HTTPS")]
    HttpsRequired,
    #[error("URL must have a host")]
    MissingHost,
    #[error("blocked hostname: {0}")]
    BlockedHostname(String),
    #[error("host not in allowlist: {0}")]
    NotInAllowlist(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    #[error("URL resolves to private/internal IP: {0}")]
    PrivateIp(IpAddr),
}

#[derive(Debug, Clone, Default)]
pub struct SsrfPolicy {
    pub allowlist: Option<HashSet<String>>,
    pub allow_private_ips: bool,
}

impl SsrfPolicy {
    pub fn strict() -> Self {
        Self {
            allowlist: None,
            allow_private_ips: false,
        }
    }

    pub fn with_allowlist(domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowlist: Some(domains.into_iter().map(Into::into).collect()),
            allow_private_ips: false,
        }
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || (ip.segments()[0] & 0xFE00) == 0xFC00 // ULA fc00::/7
        || (ip.segments()[0] & 0xFFC0) == 0xFE80 // link-local fe80::/10
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "kubernetes.default.svc",
];

pub fn validate_url(url_str: &str, policy: &SsrfPolicy) -> Result<(), SsrfError> {
    let url = Url::parse(url_str).map_err(|e| SsrfError::InvalidUrl(e.to_string()))?;

    if url.scheme() != "https" {
        return Err(SsrfError::HttpsRequired);
    }

    let host = url.host_str().ok_or(SsrfError::MissingHost)?;

    let is_allowlisted = policy
        .allowlist
        .as_ref()
        .map(|list| list.contains(host))
        .unwrap_or(false);

    if policy.allowlist.is_some() && !is_allowlisted {
        return Err(SsrfError::NotInAllowlist(host.into()));
    }

    if !is_allowlisted {
        let host_lower = host.to_lowercase();
        for blocked in BLOCKED_HOSTNAMES {
            if host_lower == *blocked || host_lower.ends_with(&format!(".{}", blocked)) {
                return Err(SsrfError::BlockedHostname(host.into()));
            }
        }
    }

    if policy.allow_private_ips {
        return Ok(());
    }

    let port = url.port().unwrap_or(443);
    let socket_addr = format!("{}:{}", host, port);

    let resolved_ips: Vec<IpAddr> = socket_addr
        .to_socket_addrs()
        .map_err(|e| SsrfError::DnsResolutionFailed(e.to_string()))?
        .map(|addr| addr.ip())
        .collect();

    if resolved_ips.is_empty() {
        return Err(SsrfError::DnsResolutionFailed(
            "no addresses returned".into(),
        ));
    }

    for ip in resolved_ips {
        if is_private_ip(ip) {
            return Err(SsrfError::PrivateIp(ip));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_http() {
        let policy = SsrfPolicy::strict();
        let result = validate_url("http://example.com/webhook", &policy);
        assert!(matches!(result, Err(SsrfError::HttpsRequired)));
    }

    #[test]
    fn test_blocks_localhost() {
        let policy = SsrfPolicy::strict();
        let result = validate_url("https://localhost/webhook", &policy);
        assert!(matches!(result, Err(SsrfError::BlockedHostname(_))));
    }

    #[test]
    fn test_blocks_cloud_metadata() {
        let policy = SsrfPolicy::strict();
        let result = validate_url("https://metadata.google.internal/computeMetadata", &policy);
        assert!(matches!(result, Err(SsrfError::BlockedHostname(_))));
    }

    #[test]
    fn test_blocks_private_ip_loopback() {
        assert!(is_private_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_blocks_private_ip_class_a() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_blocks_private_ip_class_b() {
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 15, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 32, 0, 0)));
    }

    #[test]
    fn test_blocks_private_ip_class_c() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_blocks_link_local() {
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 169, 254)));
    }

    #[test]
    fn test_blocks_cgnat() {
        assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn test_allows_public_ip() {
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_blocks_ipv6_loopback() {
        assert!(is_private_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_blocks_ipv6_ula() {
        assert!(is_private_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(Ipv6Addr::new(
            0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        )));
    }

    #[test]
    fn test_blocks_ipv6_link_local() {
        assert!(is_private_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_allowlist_rejects_non_listed() {
        let policy = SsrfPolicy::with_allowlist(["api.example.com"]);
        let result = validate_url("https://evil.com/webhook", &policy);
        assert!(matches!(result, Err(SsrfError::NotInAllowlist(_))));
    }

    #[test]
    fn test_allowlist_still_blocks_private_ip() {
        let policy = SsrfPolicy::with_allowlist(["localhost"]);
        let result = validate_url("https://localhost/webhook", &policy);
        assert!(matches!(result, Err(SsrfError::PrivateIp(_))));
    }

    #[test]
    fn test_strict_policy() {
        let policy = SsrfPolicy::strict();
        assert!(policy.allowlist.is_none());
        assert!(!policy.allow_private_ips);
    }
}
