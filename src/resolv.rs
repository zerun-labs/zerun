//! Container `/etc/resolv.conf` assembly.
//!
//! The parser is deliberately small and line-oriented: only `nameserver`,
//! `search`/`domain`, and `options` directives are understood. Host values are
//! filtered to usable addresses and syntactically safe tokens, while explicit
//! operator values are validated before they can be written into the overlay.

use std::net::IpAddr;
use std::str::FromStr;

const MAX_SEARCH_DOMAIN_LEN: usize = 253;
const MAX_DNS_OPTION_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvConf {
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    pub options: Vec<String>,
}

impl ResolvConf {
    /// Parse the host resolver configuration without trusting every line.
    pub fn from_host_text(text: &str) -> Self {
        let mut config = Self::default();
        for line in text.lines() {
            let mut fields = line
                .split_whitespace()
                .take_while(|field| !field.starts_with('#') && !field.starts_with(';'));
            let Some(directive) = fields.next() else {
                continue;
            };
            match directive {
                "nameserver" => {
                    if let Some(Ok(ip)) = fields.next().map(IpAddr::from_str) {
                        if !ip.is_loopback() {
                            push_unique(&mut config.nameservers, ip.to_string());
                        }
                    }
                }
                "search" | "domain" => {
                    for domain in fields.filter_map(|value| parse_search_domain(value).ok()) {
                        push_unique(&mut config.search, domain);
                    }
                }
                "options" => {
                    for option in fields.filter_map(|value| parse_option(value).ok()) {
                        push_unique(&mut config.options, option);
                    }
                }
                _ => {}
            }
        }
        config
    }

    /// Build the effective resolver configuration for a bridge-mode container.
    ///
    /// Host search domains and options are inherited unless the corresponding
    /// explicit list is non-empty. Nameservers fall back to public resolvers
    /// when the host only exposes loopback stub resolvers.
    pub fn effective(
        explicit_nameservers: &[String],
        explicit_search: &[String],
        explicit_options: &[String],
    ) -> Result<Self, String> {
        let host = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let mut config = Self::from_host_text(&host);
        if !explicit_nameservers.is_empty() {
            config.nameservers = explicit_nameservers
                .iter()
                .map(|value| parse_nameserver(value))
                .collect::<Result<Vec<_>, _>>()?;
            deduplicate(&mut config.nameservers);
        }
        if !explicit_search.is_empty() {
            config.search = explicit_search
                .iter()
                .map(|value| parse_search_domain(value))
                .collect::<Result<Vec<_>, _>>()?;
            deduplicate(&mut config.search);
        }
        if !explicit_options.is_empty() {
            config.options = explicit_options
                .iter()
                .map(|value| parse_option(value))
                .collect::<Result<Vec<_>, _>>()?;
            deduplicate(&mut config.options);
        }
        if config.nameservers.is_empty() {
            config.nameservers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        }
        Ok(config)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for server in &self.nameservers {
            out.push_str("nameserver ");
            out.push_str(server);
            out.push('\n');
        }
        if !self.search.is_empty() {
            out.push_str("search ");
            out.push_str(&self.search.join(" "));
            out.push('\n');
        }
        if !self.options.is_empty() {
            out.push_str("options ");
            out.push_str(&self.options.join(" "));
            out.push('\n');
        }
        out
    }
}

pub fn parse_nameserver(value: &str) -> Result<String, String> {
    value
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| format!("invalid DNS server address '{value}'"))
}

pub fn parse_search_domain(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("DNS search domain cannot be empty".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("invalid DNS search domain '{value}'"));
    }
    if value.len() > MAX_SEARCH_DOMAIN_LEN {
        return Err(format!(
            "DNS search domain '{value}' exceeds {MAX_SEARCH_DOMAIN_LEN} bytes"
        ));
    }
    if value == "." {
        return Ok(value.to_string());
    }
    let without_root = value.strip_suffix('.').unwrap_or(value);
    if without_root.is_empty()
        || without_root.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(format!("invalid DNS search domain '{value}'"));
    }
    Ok(value.to_string())
}

pub fn parse_option(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("DNS resolver option cannot be empty".to_string());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("invalid DNS resolver option '{value}'"));
    }
    if value.len() > MAX_DNS_OPTION_LEN {
        return Err(format!(
            "DNS resolver option '{value}' exceeds {MAX_DNS_OPTION_LEN} bytes"
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b',' | b'=')
    }) {
        return Err(format!("invalid DNS resolver option '{value}'"));
    }
    Ok(value.to_string())
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn deduplicate(values: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_directives_and_filters_loopback_servers() {
        let config = ResolvConf::from_host_text(
            "# host resolver\n\
             nameserver 127.0.0.53\n\
             nameserver 203.0.113.53 # primary\n\
             search svc.local corp.example\n\
             options ndots:2 rotate\n",
        );
        assert_eq!(config.nameservers, ["203.0.113.53"]);
        assert_eq!(config.search, ["svc.local", "corp.example"]);
        assert_eq!(config.options, ["ndots:2", "rotate"]);
    }

    #[test]
    fn renders_only_configured_directives_in_stable_order() {
        let config = ResolvConf {
            nameservers: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
            search: vec!["svc.local".into()],
            options: vec!["ndots:2".into(), "rotate".into()],
        };
        assert_eq!(
            config.render(),
            "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n\
             search svc.local\noptions ndots:2 rotate\n"
        );
    }

    #[test]
    fn validates_search_domains_and_options() {
        assert_eq!(parse_search_domain("svc.local.").unwrap(), "svc.local.");
        assert_eq!(parse_search_domain(".").unwrap(), ".");
        assert!(parse_search_domain(" svc.local").is_err());
        assert!(parse_search_domain("svc.local\n").is_err());
        assert!(parse_search_domain("bad domain").is_err());
        assert!(parse_search_domain("bad..domain").is_err());
        assert!(parse_search_domain("bad/domain").is_err());

        assert_eq!(parse_option("ndots:2").unwrap(), "ndots:2");
        assert_eq!(
            parse_option("single-request-reopen").unwrap(),
            "single-request-reopen"
        );
        assert!(parse_option("\trotate").is_err());
        assert!(parse_option("rotate\n").is_err());
        assert!(parse_option("ndots:2 rotate").is_err());
        assert!(parse_option("bad#comment").is_err());
    }

    #[test]
    fn nameservers_are_canonicalized_and_validated() {
        assert_eq!(parse_nameserver("2001:0db8::1").unwrap(), "2001:db8::1");
        assert!(parse_nameserver("dns.example").is_err());
    }

    #[test]
    fn explicit_values_replace_host_values_and_are_deduplicated() {
        let config = ResolvConf::effective(
            &["1.1.1.1".into(), "1.1.1.1".into()],
            &["svc.local".into(), "svc.local".into()],
            &["ndots:2".into(), "ndots:2".into()],
        )
        .unwrap();
        assert_eq!(config.nameservers, ["1.1.1.1"]);
        assert_eq!(config.search, ["svc.local"]);
        assert_eq!(config.options, ["ndots:2"]);
    }
}
