use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use log::{debug, info, warn};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::capture::packet::{Direction, PacketInfo, Protocol, TcpFlags};

/// Represents a detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: String,

    /// Alert message
    pub message: String,

    /// Rule severity (critical, high, medium, low)
    pub severity: String,

    /// Source IP address or CIDR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    /// Destination IP address or CIDR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,

    /// Source port or range
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<String>,

    /// Destination port or range
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<String>,

    /// Protocol
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Direction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,

    /// Regular expression pattern to match against packet payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_pattern: Option<String>,

    /// Compiled regex pattern (not serialized)
    #[serde(skip)]
    pub compiled_pattern: Option<Regex>,

    /// Rule category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// TCP flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<String>,

    /// Whether the rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Reference links
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Rule {
    /// Create a new rule
    pub fn new(id: String, name: String, message: String, severity: String) -> Self {
        Self {
            id,
            name,
            description: String::new(),
            message,
            severity,
            source_ip: None,
            destination_ip: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            direction: None,
            payload_pattern: None,
            compiled_pattern: None,
            category: None,
            tcp_flags: None,
            enabled: true,
            references: Vec::new(),
        }
    }

    /// Compile regular expression pattern if present
    pub fn compile_pattern(&mut self) -> Result<()> {
        if let Some(pattern) = &self.payload_pattern {
            let regex = Regex::new(pattern)
                .with_context(|| format!("Failed to compile regex pattern: {}", pattern))?;
            self.compiled_pattern = Some(regex);
        }
        Ok(())
    }

    /// Check if this rule matches a packet
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        // Skip if rule is disabled
        if !self.enabled {
            return false;
        }

        // Check source IP
        if let Some(source_ip) = &self.source_ip {
            if !self.check_ip_match(&packet.source_ip, source_ip) {
                return false;
            }
        }

        // Check destination IP
        if let Some(destination_ip) = &self.destination_ip {
            if !self.check_ip_match(&packet.destination_ip, destination_ip) {
                return false;
            }
        }

        // Check source port
        if let Some(source_port) = &self.source_port {
            if let Some(packet_source_port) = packet.source_port {
                if !self.check_port_match(packet_source_port, source_port) {
                    return false;
                }
            } else {
                // Rule requires source port but packet doesn't have one
                return false;
            }
        }

        // Check destination port
        if let Some(destination_port) = &self.destination_port {
            if let Some(packet_destination_port) = packet.destination_port {
                if !self.check_port_match(packet_destination_port, destination_port) {
                    return false;
                }
            } else {
                // Rule requires destination port but packet doesn't have one
                return false;
            }
        }

        // Check protocol
        if let Some(protocol) = &self.protocol {
            if !self.check_protocol_match(&packet.protocol, protocol) {
                return false;
            }
        }

        // Check direction
        if let Some(direction) = &self.direction {
            if !self.check_direction_match(&packet.direction, direction) {
                return false;
            }
        }

        // Check TCP flags
        if let Some(tcp_flags) = &self.tcp_flags {
            if let Some(packet_tcp_flags) = &packet.tcp_flags {
                if !self.check_tcp_flags_match(packet_tcp_flags, tcp_flags) {
                    return false;
                }
            } else {
                // Rule requires TCP flags but packet doesn't have them
                return false;
            }
        }

        // Check payload pattern
        if let Some(regex) = &self.compiled_pattern {
            match &packet.payload {
                Some(body) => {
                    if !regex.is_match(body) {
                        return false;
                    }
                }
                None => {
                    warn!("Cannot check payload pattern without actual payload data");
                    return false;
                }
            }
        }

        // All checks passed, rule matches
        true
    }

    /// Check if an IP address matches a rule IP specification (exact IP or CIDR)
    fn check_ip_match(&self, packet_ip: &IpAddr, rule_ip: &str) -> bool {
        // Check if this is a CIDR notation
        if rule_ip.contains('/') {
            self.check_ip_cidr_match(packet_ip, rule_ip)
        } else {
            // Exact IP match
            match IpAddr::from_str(rule_ip) {
                Ok(ip) => *packet_ip == ip,
                Err(_) => {
                    warn!("Invalid IP address in rule: {}", rule_ip);
                    false
                }
            }
        }
    }

    /// Check if an IP address matches a CIDR specification
    fn check_ip_cidr_match(&self, packet_ip: &IpAddr, cidr: &str) -> bool {
        // Parse CIDR
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            warn!("Invalid CIDR notation: {}", cidr);
            return false;
        }

        let ip_str = parts[0];
        let prefix_len = match parts[1].parse::<u8>() {
            Ok(len) => len,
            Err(_) => {
                warn!("Invalid prefix length in CIDR: {}", cidr);
                return false;
            }
        };

        // Handle IPv4
        if let Ok(network_ip) = Ipv4Addr::from_str(ip_str) {
            if let IpAddr::V4(packet_ipv4) = packet_ip {
                // Convert IPs to u32 for easier comparison
                let network_bits = u32::from(network_ip);
                let packet_bits = u32::from(*packet_ipv4);

                // Calculate network mask
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };

                // Check if packet IP is in network
                (network_bits & mask) == (packet_bits & mask)
            } else {
                // Rule is IPv4 but packet is IPv6
                false
            }
        }
        // Handle IPv6
        else if let Ok(network_ip) = Ipv6Addr::from_str(ip_str) {
            if let IpAddr::V6(packet_ipv6) = packet_ip {
                // Convert IPs to u128 for easier comparison
                let network_bits = u128::from(network_ip);
                let packet_bits = u128::from(*packet_ipv6);

                // Calculate network mask
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };

                // Check if packet IP is in network
                (network_bits & mask) == (packet_bits & mask)
            } else {
                // Rule is IPv6 but packet is IPv4
                false
            }
        } else {
            warn!("Invalid IP address in CIDR: {}", cidr);
            false
        }
    }

    /// Check if a port matches a rule port specification (exact port or range)
    fn check_port_match(&self, packet_port: u16, rule_port: &str) -> bool {
        // Check if this is a port range
        if rule_port.contains(':') {
            // Parse port range
            let parts: Vec<&str> = rule_port.split(':').collect();
            if parts.len() != 2 {
                warn!("Invalid port range: {}", rule_port);
                return false;
            }

            let min_port = match parts[0].parse::<u16>() {
                Ok(port) => port,
                Err(_) => {
                    warn!("Invalid port number: {}", parts[0]);
                    return false;
                }
            };

            let max_port = match parts[1].parse::<u16>() {
                Ok(port) => port,
                Err(_) => {
                    warn!("Invalid port number: {}", parts[1]);
                    return false;
                }
            };

            // Check if port is in range
            packet_port >= min_port && packet_port <= max_port
        } else {
            // Exact port match
            match rule_port.parse::<u16>() {
                Ok(port) => packet_port == port,
                Err(_) => {
                    warn!("Invalid port number: {}", rule_port);
                    false
                }
            }
        }
    }

    /// Check if a protocol matches a rule protocol specification
    fn check_protocol_match(&self, packet_protocol: &Protocol, rule_protocol: &str) -> bool {
        match rule_protocol.to_lowercase().as_str() {
            "tcp" => matches!(packet_protocol, Protocol::TCP | Protocol::HTTP | Protocol::HTTPS | Protocol::SSH | Protocol::FTP | Protocol::SMTP | Protocol::POP3 | Protocol::IMAP),
            "udp" => matches!(packet_protocol, Protocol::UDP | Protocol::DNS | Protocol::DHCP),
            "icmp" => matches!(packet_protocol, Protocol::ICMP),
            "http" => matches!(packet_protocol, Protocol::HTTP),
            "https" => matches!(packet_protocol, Protocol::HTTPS),
            "dns" => matches!(packet_protocol, Protocol::DNS),
            "ssh" => matches!(packet_protocol, Protocol::SSH),
            "ftp" => matches!(packet_protocol, Protocol::FTP),
            "smtp" => matches!(packet_protocol, Protocol::SMTP),
            "pop3" => matches!(packet_protocol, Protocol::POP3),
            "imap" => matches!(packet_protocol, Protocol::IMAP),
            "dhcp" => matches!(packet_protocol, Protocol::DHCP),
            "arp" => matches!(packet_protocol, Protocol::ARP),
            "any" => true,
            _ => {
                warn!("Unsupported protocol in rule: {}", rule_protocol);
                false
            }
        }
    }

    /// Check if a direction matches a rule direction specification
    fn check_direction_match(&self, packet_direction: &Direction, rule_direction: &str) -> bool {
        match rule_direction.to_lowercase().as_str() {
            "inbound" => *packet_direction == Direction::Inbound,
            "outbound" => *packet_direction == Direction::Outbound,
            "internal" => *packet_direction == Direction::Internal,
            "external" => *packet_direction == Direction::External,
            "any" => true,
            _ => {
                warn!("Unsupported direction in rule: {}", rule_direction);
                false
            }
        }
    }

    /// Check if TCP flags match a rule TCP flags specification
    fn check_tcp_flags_match(&self, packet_flags: &TcpFlags, rule_flags: &str) -> bool {
        // Parse the rule flags
        for flag in rule_flags.chars() {
            match flag {
                'S' | 's' => if !packet_flags.syn { return false; },
                'A' | 'a' => if !packet_flags.ack { return false; },
                'F' | 'f' => if !packet_flags.fin { return false; },
                'R' | 'r' => if !packet_flags.rst { return false; },
                'P' | 'p' => if !packet_flags.psh { return false; },
                'U' | 'u' => if !packet_flags.urg { return false; },
                'E' | 'e' => if !packet_flags.ece { return false; },
                'C' | 'c' => if !packet_flags.cwr { return false; },
                '+' => {}, // Ignore, used to separate flags
                _ => {
                    warn!("Unsupported TCP flag in rule: {}", flag);
                    return false;
                }
            }
        }

        true
    }
}

/// Helper for loading rules from files
pub struct RuleLoader {
    /// Directory containing rule files
    rules_dir: PathBuf,
}

impl RuleLoader {
    /// Create a new rule loader
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Self {
        Self {
            rules_dir: rules_dir.as_ref().to_path_buf(),
        }
    }

    /// Load all rules from the rules directory
    pub fn load_rules(&self) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        // Check if directory exists
        if !self.rules_dir.exists() {
            // Create default rules
            let default_rules = self.create_default_rules()?;
            return Ok(default_rules);
        }

        // Read all rule files
        for entry in fs::read_dir(&self.rules_dir).context("Failed to read rules directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Only process JSON files
            if path.extension().map_or(false, |ext| ext == "json") {
                match self.load_rule_file(&path) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => warn!("Failed to load rule file {:?}: {}", path, e),
                }
            }
        }

        // If no rules were loaded, create default rules
        if rules.is_empty() {
            info!("No rules found, creating default rules");
            rules = self.create_default_rules()?;
        }

        Ok(rules)
    }

    /// Load a single rule file
    fn load_rule_file(&self, path: &PathBuf) -> Result<Rule> {
        // Read file
        let rule_json = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rule file: {:?}", path))?;

        // Parse JSON
        let mut rule: Rule = serde_json::from_str(&rule_json)
            .with_context(|| format!("Failed to parse rule file: {:?}", path))?;

        // Compile regex pattern if present
        rule.compile_pattern()
            .with_context(|| format!("Failed to compile regex pattern in rule file: {:?}", path))?;

        Ok(rule)
    }

    /// Create default rules
    fn create_default_rules(&self) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        // Create some basic rules

        // Rule 1: Detect ping sweep (ICMP echo request)
        let mut rule1 = Rule::new(
            "1000001".to_string(),
            "ICMP Echo Request".to_string(),
            "Potential ping sweep detected".to_string(),
            "low".to_string(),
        );
        rule1.protocol = Some("icmp".to_string());
        rule1.direction = Some("inbound".to_string());
        rule1.description = "Detects ICMP echo request packets".to_string();
        rule1.category = Some("recon".to_string());
        rules.push(rule1);

        // Rule 2: Detect SSH brute force attempts
        let mut rule2 = Rule::new(
            "1000002".to_string(),
            "SSH Brute Force".to_string(),
            "Potential SSH brute force attack detected".to_string(),
            "medium".to_string(),
        );
        rule2.protocol = Some("ssh".to_string());
        rule2.destination_port = Some("22".to_string());
        rule2.direction = Some("inbound".to_string());
        rule2.description = "Detects potential SSH brute force attacks".to_string();
        rule2.category = Some("bruteforce".to_string());
        rules.push(rule2);

        // Rule 3: Detect port scanning
        let mut rule3 = Rule::new(
            "1000003".to_string(),
            "TCP Port Scan".to_string(),
            "Potential port scanning activity detected".to_string(),
            "medium".to_string(),
        );
        rule3.protocol = Some("tcp".to_string());
        rule3.tcp_flags = Some("S".to_string()); // SYN packets only
        rule3.direction = Some("inbound".to_string());
        rule3.description = "Detects TCP SYN packets that may indicate port scanning".to_string();
        rule3.category = Some("recon".to_string());
        rules.push(rule3);

        // Rule 4: Detect HTTP directory traversal attempts
        let mut rule4 = Rule::new(
            "1000004".to_string(),
            "HTTP Directory Traversal".to_string(),
            "Potential directory traversal attack detected".to_string(),
            "high".to_string(),
        );
        rule4.protocol = Some("http".to_string());
        rule4.direction = Some("inbound".to_string());
        rule4.payload_pattern = Some(r"\.\.[\\/]".to_string());
        rule4.description = "Detects attempts to access files using directory traversal techniques".to_string();
        rule4.category = Some("web-attack".to_string());
        rule4.compile_pattern()?;
        rules.push(rule4);

        // Rule 5: Detect DNS tunneling
        let mut rule5 = Rule::new(
            "1000005".to_string(),
            "DNS Tunneling".to_string(),
            "Potential DNS tunneling detected".to_string(),
            "high".to_string(),
        );
        rule5.protocol = Some("dns".to_string());
        rule5.direction = Some("outbound".to_string());
        rule5.description = "Detects potentially suspicious DNS queries that may indicate tunneling".to_string();
        rule5.category = Some("data-exfiltration".to_string());
        rules.push(rule5);

        // Advanced Security Rules

        // Rule 6: SQL Injection Attempts
        let mut rule6 = Rule::new(
            "1000006".to_string(),
            "SQL Injection Attack".to_string(),
            "SQL injection attempt detected".to_string(),
            "critical".to_string(),
        );
        rule6.protocol = Some("http".to_string());
        rule6.direction = Some("inbound".to_string());
        rule6.payload_pattern = Some(r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec.*\(|execute.*\(|';.*--|--.*\n)".to_string());
        rule6.description = "Detects common SQL injection patterns in HTTP requests".to_string();
        rule6.category = Some("web-attack".to_string());
        rule6.references = vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()];
        rule6.compile_pattern()?;
        rules.push(rule6);

        // Rule 7: XSS Attempts
        let mut rule7 = Rule::new(
            "1000007".to_string(),
            "Cross-Site Scripting (XSS)".to_string(),
            "XSS attack attempt detected".to_string(),
            "high".to_string(),
        );
        rule7.protocol = Some("http".to_string());
        rule7.direction = Some("inbound".to_string());
        rule7.payload_pattern = Some(r"(?i)(<script[^>]*>.*?</script>|javascript:|onerror=|onload=|onclick=|<iframe|<embed|<object)".to_string());
        rule7.description = "Detects potential XSS attack patterns".to_string();
        rule7.category = Some("web-attack".to_string());
        rule7.compile_pattern()?;
        rules.push(rule7);

        // Rule 8: Command Injection
        let mut rule8 = Rule::new(
            "1000008".to_string(),
            "Command Injection".to_string(),
            "Command injection attempt detected".to_string(),
            "critical".to_string(),
        );
        rule8.protocol = Some("http".to_string());
        rule8.direction = Some("inbound".to_string());
        rule8.payload_pattern = Some(r"(?i)(\||;|`|\$\(|&&|\|\||>|<).*?(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|wget|curl|chmod|chown)".to_string());
        rule8.description = "Detects command injection attempts".to_string();
        rule8.category = Some("web-attack".to_string());
        rule8.compile_pattern()?;
        rules.push(rule8);

        // Rule 9: DDoS Detection - SYN Flood
        let mut rule9 = Rule::new(
            "1000009".to_string(),
            "SYN Flood Attack".to_string(),
            "Potential SYN flood DDoS attack detected".to_string(),
            "critical".to_string(),
        );
        rule9.protocol = Some("tcp".to_string());
        rule9.tcp_flags = Some("S".to_string());
        rule9.direction = Some("inbound".to_string());
        rule9.description = "Detects excessive SYN packets indicating possible DDoS".to_string();
        rule9.category = Some("dos".to_string());
        rules.push(rule9);

        // Rule 10: Malware C&C Communication
        let mut rule10 = Rule::new(
            "1000010".to_string(),
            "Malware Command & Control".to_string(),
            "Potential malware C&C communication detected".to_string(),
            "critical".to_string(),
        );
        rule10.protocol = Some("tcp".to_string());
        rule10.destination_port = Some("4444:4450".to_string()); // Common malware ports
        rule10.direction = Some("outbound".to_string());
        rule10.description = "Detects outbound connections to common malware C&C ports".to_string();
        rule10.category = Some("malware".to_string());
        rules.push(rule10);

        // Rule 11: RDP Brute Force
        let mut rule11 = Rule::new(
            "1000011".to_string(),
            "RDP Brute Force".to_string(),
            "RDP brute force attack detected".to_string(),
            "high".to_string(),
        );
        rule11.protocol = Some("tcp".to_string());
        rule11.destination_port = Some("3389".to_string());
        rule11.direction = Some("inbound".to_string());
        rule11.description = "Detects potential RDP brute force attempts".to_string();
        rule11.category = Some("bruteforce".to_string());
        rules.push(rule11);

        // Rule 12: FTP Brute Force
        let mut rule12 = Rule::new(
            "1000012".to_string(),
            "FTP Brute Force".to_string(),
            "FTP brute force attack detected".to_string(),
            "medium".to_string(),
        );
        rule12.protocol = Some("ftp".to_string());
        rule12.destination_port = Some("21".to_string());
        rule12.direction = Some("inbound".to_string());
        rule12.description = "Detects FTP brute force attempts".to_string();
        rule12.category = Some("bruteforce".to_string());
        rules.push(rule12);

        // Rule 13: Telnet Access Attempt
        let mut rule13 = Rule::new(
            "1000013".to_string(),
            "Telnet Access Attempt".to_string(),
            "Insecure Telnet connection attempt detected".to_string(),
            "high".to_string(),
        );
        rule13.protocol = Some("tcp".to_string());
        rule13.destination_port = Some("23".to_string());
        rule13.direction = Some("any".to_string());
        rule13.description = "Detects Telnet usage which is insecure".to_string();
        rule13.category = Some("policy-violation".to_string());
        rules.push(rule13);

        // Rule 14: SMB/NetBIOS Scanning
        let mut rule14 = Rule::new(
            "1000014".to_string(),
            "SMB/NetBIOS Scan".to_string(),
            "SMB/NetBIOS scanning detected".to_string(),
            "medium".to_string(),
        );
        rule14.protocol = Some("tcp".to_string());
        rule14.destination_port = Some("135:139".to_string());
        rule14.direction = Some("inbound".to_string());
        rule14.description = "Detects SMB/NetBIOS scanning activity".to_string();
        rule14.category = Some("recon".to_string());
        rules.push(rule14);

        // Rule 15: WannaCry Ransomware Detection
        let mut rule15 = Rule::new(
            "1000015".to_string(),
            "WannaCry Ransomware".to_string(),
            "WannaCry ransomware activity detected".to_string(),
            "critical".to_string(),
        );
        rule15.protocol = Some("tcp".to_string());
        rule15.destination_port = Some("445".to_string());
        rule15.direction = Some("any".to_string());
        rule15.payload_pattern = Some(r"(?i)(wannacry|wncry|wcry|wanacrypt)".to_string());
        rule15.description = "Detects potential WannaCry ransomware activity".to_string();
        rule15.category = Some("malware".to_string());
        rule15.references = vec!["https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware".to_string()];
        rule15.compile_pattern()?;
        rules.push(rule15);

        // Rule 16: Cryptomining Detection
        let mut rule16 = Rule::new(
            "1000016".to_string(),
            "Cryptocurrency Mining".to_string(),
            "Unauthorized cryptocurrency mining detected".to_string(),
            "high".to_string(),
        );
        rule16.protocol = Some("tcp".to_string());
        rule16.destination_port = Some("3333:3335".to_string()); // Common mining pool ports
        rule16.direction = Some("outbound".to_string());
        rule16.description = "Detects connections to common cryptocurrency mining pools".to_string();
        rule16.category = Some("malware".to_string());
        rules.push(rule16);

        // Rule 17: Log4j Exploit Attempt
        let mut rule17 = Rule::new(
            "1000017".to_string(),
            "Log4j Exploit Attempt".to_string(),
            "Log4Shell vulnerability exploit attempt detected".to_string(),
            "critical".to_string(),
        );
        rule17.protocol = Some("http".to_string());
        rule17.direction = Some("inbound".to_string());
        rule17.payload_pattern = Some(r"\$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http)://".to_string());
        rule17.description = "Detects Log4j vulnerability exploitation attempts".to_string();
        rule17.category = Some("exploit".to_string());
        rule17.references = vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()];
        rule17.compile_pattern()?;
        rules.push(rule17);

        // Rule 18: Tor Network Traffic
        let mut rule18 = Rule::new(
            "1000018".to_string(),
            "Tor Network Traffic".to_string(),
            "Tor network usage detected".to_string(),
            "medium".to_string(),
        );
        rule18.protocol = Some("tcp".to_string());
        rule18.destination_port = Some("9001:9051".to_string());
        rule18.direction = Some("outbound".to_string());
        rule18.description = "Detects potential Tor network traffic".to_string();
        rule18.category = Some("anonymizer".to_string());
        rules.push(rule18);

        // Rule 19: DNS Over HTTPS (DoH)
        let mut rule19 = Rule::new(
            "1000019".to_string(),
            "DNS over HTTPS".to_string(),
            "DNS over HTTPS traffic detected".to_string(),
            "low".to_string(),
        );
        rule19.protocol = Some("https".to_string());
        rule19.destination_port = Some("443".to_string());
        rule19.payload_pattern = Some(r"application/dns-message".to_string());
        rule19.direction = Some("outbound".to_string());
        rule19.description = "Detects DNS over HTTPS which may bypass DNS filtering".to_string();
        rule19.category = Some("policy-violation".to_string());
        rule19.compile_pattern()?;
        rules.push(rule19);

        // Rule 20: Data Exfiltration via ICMP
        let mut rule20 = Rule::new(
            "1000020".to_string(),
            "ICMP Data Exfiltration".to_string(),
            "Potential data exfiltration via ICMP detected".to_string(),
            "high".to_string(),
        );
        rule20.protocol = Some("icmp".to_string());
        rule20.direction = Some("outbound".to_string());
        rule20.description = "Detects unusually large ICMP packets that may contain exfiltrated data".to_string();
        rule20.category = Some("data-exfiltration".to_string());
        rules.push(rule20);

        // Rule 21: Privilege Escalation Attempt
        let mut rule21 = Rule::new(
            "1000021".to_string(),
            "Privilege Escalation".to_string(),
            "Privilege escalation attempt detected".to_string(),
            "critical".to_string(),
        );
        rule21.protocol = Some("http".to_string());
        rule21.direction = Some("inbound".to_string());
        rule21.payload_pattern = Some(r"(?i)(sudo|su\s+root|passwd|shadow|sudoers|privilege|escalat)".to_string());
        rule21.description = "Detects attempts to escalate privileges".to_string();
        rule21.category = Some("exploit".to_string());
        rule21.compile_pattern()?;
        rules.push(rule21);

        // Rule 22: Reverse Shell Detection
        let mut rule22 = Rule::new(
            "1000022".to_string(),
            "Reverse Shell".to_string(),
            "Reverse shell connection detected".to_string(),
            "critical".to_string(),
        );
        rule22.protocol = Some("tcp".to_string());
        rule22.destination_port = Some("1337".to_string()); // Common reverse shell port
        rule22.direction = Some("outbound".to_string());
        rule22.description = "Detects potential reverse shell connections".to_string();
        rule22.category = Some("backdoor".to_string());
        rules.push(rule22);

        // Rule 23: LDAP Injection
        let mut rule23 = Rule::new(
            "1000023".to_string(),
            "LDAP Injection".to_string(),
            "LDAP injection attempt detected".to_string(),
            "high".to_string(),
        );
        rule23.protocol = Some("tcp".to_string());
        rule23.destination_port = Some("389".to_string());
        rule23.payload_pattern = Some(r"[)(|&=*]|\)|\(|\|".to_string());
        rule23.description = "Detects LDAP injection attempts".to_string();
        rule23.category = Some("injection-attack".to_string());
        rule23.compile_pattern()?;
        rules.push(rule23);

        // Rule 24: XML External Entity (XXE) Attack
        let mut rule24 = Rule::new(
            "1000024".to_string(),
            "XXE Attack".to_string(),
            "XML External Entity attack detected".to_string(),
            "high".to_string(),
        );
        rule24.protocol = Some("http".to_string());
        rule24.direction = Some("inbound".to_string());
        rule24.payload_pattern = Some(r"<!ENTITY.*SYSTEM|<!DOCTYPE.*\[<!ENTITY".to_string());
        rule24.description = "Detects XML External Entity (XXE) attack attempts".to_string();
        rule24.category = Some("web-attack".to_string());
        rule24.compile_pattern()?;
        rules.push(rule24);

        // Rule 25: Heartbleed Exploit
        let mut rule25 = Rule::new(
            "1000025".to_string(),
            "Heartbleed Exploit".to_string(),
            "Heartbleed vulnerability exploit attempt detected".to_string(),
            "critical".to_string(),
        );
        rule25.protocol = Some("https".to_string());
        rule25.destination_port = Some("443".to_string());
        rule25.payload_pattern = Some(r"\x18\x03[\x00-\x03][\x00-\x03]\x40".to_string());
        rule25.description = "Detects Heartbleed SSL vulnerability exploitation".to_string();
        rule25.category = Some("exploit".to_string());
        rule25.references = vec!["https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string()];
        rule25.compile_pattern()?;
        rules.push(rule25);

        // Rule 26: Shellshock Exploit
        let mut rule26 = Rule::new(
            "1000026".to_string(),
            "Shellshock Exploit".to_string(),
            "Shellshock vulnerability exploit detected".to_string(),
            "critical".to_string(),
        );
        rule26.protocol = Some("http".to_string());
        rule26.direction = Some("inbound".to_string());
        rule26.payload_pattern = Some(r"\(\s*\)\s*\{[^}]*:[^}]*;[^}]*\}".to_string());
        rule26.description = "Detects Shellshock bash vulnerability exploitation".to_string();
        rule26.category = Some("exploit".to_string());
        rule26.references = vec!["https://nvd.nist.gov/vuln/detail/CVE-2014-6271".to_string()];
        rule26.compile_pattern()?;
        rules.push(rule26);

        // Rule 27: Suspicious PowerShell Commands
        let mut rule27 = Rule::new(
            "1000027".to_string(),
            "Suspicious PowerShell".to_string(),
            "Suspicious PowerShell command detected".to_string(),
            "high".to_string(),
        );
        rule27.protocol = Some("http".to_string());
        rule27.direction = Some("any".to_string());
        rule27.payload_pattern = Some(r"(?i)(powershell.*-enc|-encodedcommand|iex\s*\(|invoke-expression|downloadstring)".to_string());
        rule27.description = "Detects suspicious PowerShell commands often used in attacks".to_string();
        rule27.category = Some("malware".to_string());
        rule27.compile_pattern()?;
        rules.push(rule27);

        // Rule 28: Buffer Overflow Attempt
        let mut rule28 = Rule::new(
            "1000028".to_string(),
            "Buffer Overflow".to_string(),
            "Buffer overflow attempt detected".to_string(),
            "critical".to_string(),
        );
        rule28.protocol = Some("tcp".to_string());
        rule28.direction = Some("inbound".to_string());
        rule28.payload_pattern = Some(r"(\x90{10,}|\x41{100,}|\x00{50,})".to_string());
        rule28.description = "Detects potential buffer overflow patterns (NOP sleds, long strings)".to_string();
        rule28.category = Some("exploit".to_string());
        rule28.compile_pattern()?;
        rules.push(rule28);

        // Rule 29: Mimikatz Usage
        let mut rule29 = Rule::new(
            "1000029".to_string(),
            "Mimikatz Tool".to_string(),
            "Mimikatz credential theft tool detected".to_string(),
            "critical".to_string(),
        );
        rule29.protocol = Some("tcp".to_string());
        rule29.direction = Some("any".to_string());
        rule29.payload_pattern = Some(r"(?i)(mimikatz|sekurlsa|lsadump|gentilkiwi)".to_string());
        rule29.description = "Detects Mimikatz tool usage for credential theft".to_string();
        rule29.category = Some("credential-theft".to_string());
        rule29.compile_pattern()?;
        rules.push(rule29);

        // Rule 30: Zero-Day Exploit Pattern
        let mut rule30 = Rule::new(
            "1000030".to_string(),
            "Zero-Day Pattern".to_string(),
            "Potential zero-day exploit pattern detected".to_string(),
            "critical".to_string(),
        );
        rule30.protocol = Some("tcp".to_string());
        rule30.tcp_flags = Some("PSH+ACK".to_string());
        rule30.direction = Some("inbound".to_string());
        rule30.description = "Detects unusual packet patterns that may indicate zero-day exploits".to_string();
        rule30.category = Some("anomaly".to_string());
        rules.push(rule30);

        // Rule 31: Botnet C&C Beacon
        let mut rule31 = Rule::new(
            "1000031".to_string(),
            "Botnet Beacon".to_string(),
            "Botnet command and control beacon detected".to_string(),
            "critical".to_string(),
        );
        rule31.protocol = Some("tcp".to_string());
        rule31.destination_port = Some("6667".to_string()); // IRC port often used by botnets
        rule31.direction = Some("outbound".to_string());
        rule31.description = "Detects potential botnet C&C communication".to_string();
        rule31.category = Some("malware".to_string());
        rules.push(rule31);

        // Rule 32: ARP Spoofing
        let mut rule32 = Rule::new(
            "1000032".to_string(),
            "ARP Spoofing".to_string(),
            "ARP spoofing attack detected".to_string(),
            "high".to_string(),
        );
        rule32.protocol = Some("arp".to_string());
        rule32.direction = Some("any".to_string());
        rule32.description = "Detects ARP spoofing/poisoning attempts".to_string();
        rule32.category = Some("mitm".to_string());
        rules.push(rule32);

        // Rule 33: SMTP Open Relay Test
        let mut rule33 = Rule::new(
            "1000033".to_string(),
            "SMTP Open Relay".to_string(),
            "SMTP open relay test detected".to_string(),
            "medium".to_string(),
        );
        rule33.protocol = Some("smtp".to_string());
        rule33.destination_port = Some("25".to_string());
        rule33.payload_pattern = Some(r"(?i)(rcpt to:|mail from:|vrfy|expn)".to_string());
        rule33.description = "Detects attempts to test for SMTP open relay".to_string();
        rule33.category = Some("recon".to_string());
        rule33.compile_pattern()?;
        rules.push(rule33);

        // Rule 34: VPN Detection
        let mut rule34 = Rule::new(
            "1000034".to_string(),
            "VPN Traffic".to_string(),
            "VPN traffic detected".to_string(),
            "low".to_string(),
        );
        rule34.protocol = Some("udp".to_string());
        rule34.destination_port = Some("500".to_string()); // IPSec IKE
        rule34.direction = Some("any".to_string());
        rule34.description = "Detects VPN traffic (may be legitimate or policy violation)".to_string();
        rule34.category = Some("policy-violation".to_string());
        rules.push(rule34);

        // Rule 35: DNS Cache Poisoning
        let mut rule35 = Rule::new(
            "1000035".to_string(),
            "DNS Cache Poisoning".to_string(),
            "DNS cache poisoning attempt detected".to_string(),
            "high".to_string(),
        );
        rule35.protocol = Some("dns".to_string());
        rule35.direction = Some("inbound".to_string());
        rule35.description = "Detects potential DNS cache poisoning attempts".to_string();
        rule35.category = Some("dns-attack".to_string());
        rules.push(rule35);

        // Rule 36: Remote Access Trojan (RAT)
        let mut rule36 = Rule::new(
            "1000036".to_string(),
            "Remote Access Trojan".to_string(),
            "Remote Access Trojan activity detected".to_string(),
            "critical".to_string(),
        );
        rule36.protocol = Some("tcp".to_string());
        rule36.destination_port = Some("5552:5555".to_string()); // Common RAT ports
        rule36.direction = Some("outbound".to_string());
        rule36.description = "Detects potential Remote Access Trojan communication".to_string();
        rule36.category = Some("malware".to_string());
        rules.push(rule36);

        // Rule 37: Credential Stuffing
        let mut rule37 = Rule::new(
            "1000037".to_string(),
            "Credential Stuffing".to_string(),
            "Credential stuffing attack detected".to_string(),
            "high".to_string(),
        );
        rule37.protocol = Some("http".to_string());
        rule37.direction = Some("inbound".to_string());
        rule37.payload_pattern = Some(r"(?i)(login|signin|auth).*password=".to_string());
        rule37.description = "Detects high-volume login attempts indicating credential stuffing".to_string();
        rule37.category = Some("bruteforce".to_string());
        rule37.compile_pattern()?;
        rules.push(rule37);

        // Rule 38: Malicious File Upload
        let mut rule38 = Rule::new(
            "1000038".to_string(),
            "Malicious File Upload".to_string(),
            "Potentially malicious file upload detected".to_string(),
            "high".to_string(),
        );
        rule38.protocol = Some("http".to_string());
        rule38.direction = Some("inbound".to_string());
        rule38.payload_pattern = Some(r"(?i)(\.php|\.jsp|\.asp|\.exe|\.bat|\.ps1|\.sh).*multipart/form-data".to_string());
        rule38.description = "Detects uploads of potentially malicious file types".to_string();
        rule38.category = Some("web-attack".to_string());
        rule38.compile_pattern()?;
        rules.push(rule38);

        // Rule 39: Blockchain/Cryptocurrency Theft
        let mut rule39 = Rule::new(
            "1000039".to_string(),
            "Crypto Wallet Attack".to_string(),
            "Cryptocurrency wallet attack detected".to_string(),
            "critical".to_string(),
        );
        rule39.protocol = Some("tcp".to_string());
        rule39.destination_port = Some("8332:8333".to_string()); // Bitcoin ports
        rule39.direction = Some("outbound".to_string());
        rule39.description = "Detects potential cryptocurrency wallet attacks".to_string();
        rule39.category = Some("financial-attack".to_string());
        rules.push(rule39);

        // Rule 40: Advanced Persistent Threat (APT) Indicator
        let mut rule40 = Rule::new(
            "1000040".to_string(),
            "APT Indicator".to_string(),
            "Advanced Persistent Threat activity detected".to_string(),
            "critical".to_string(),
        );
        rule40.protocol = Some("tcp".to_string());
        rule40.direction = Some("outbound".to_string());
        rule40.payload_pattern = Some(r"(?i)(cobaltstrike|empire|metasploit|covenant)".to_string());
        rule40.description = "Detects indicators of APT tools and frameworks".to_string();
        rule40.category = Some("apt".to_string());
        rule40.compile_pattern()?;
        rules.push(rule40);

        // Rule 41: Ransomware File Encryption Pattern
        let mut rule41 = Rule::new(
            "1000041".to_string(),
            "Ransomware Encryption".to_string(),
            "Ransomware file encryption activity detected".to_string(),
            "critical".to_string(),
        );
        rule41.protocol = Some("tcp".to_string());
        rule41.direction = Some("any".to_string());
        rule41.payload_pattern = Some(r"(?i)(\.encrypted|\.locked|\.crypto|ransom|bitcoin|monero|decrypt|payment)".to_string());
        rule41.description = "Detects patterns associated with ransomware file encryption".to_string();
        rule41.category = Some("ransomware".to_string());
        rule41.compile_pattern()?;
        rules.push(rule41);

        // Rule 42: Lateral Movement Detection
        let mut rule42 = Rule::new(
            "1000042".to_string(),
            "Lateral Movement".to_string(),
            "Lateral movement in network detected".to_string(),
            "critical".to_string(),
        );
        rule42.protocol = Some("tcp".to_string());
        rule42.destination_port = Some("445".to_string());
        rule42.direction = Some("internal".to_string());
        rule42.description = "Detects potential lateral movement using SMB".to_string();
        rule42.category = Some("lateral-movement".to_string());
        rules.push(rule42);

        // Rule 43: Domain Generation Algorithm (DGA)
        let mut rule43 = Rule::new(
            "1000043".to_string(),
            "DGA Detection".to_string(),
            "Domain Generation Algorithm activity detected".to_string(),
            "high".to_string(),
        );
        rule43.protocol = Some("dns".to_string());
        rule43.direction = Some("outbound".to_string());
        rule43.payload_pattern = Some(r"[a-z]{20,}\.(?:com|net|org|info|biz)".to_string());
        rule43.description = "Detects suspicious DNS queries that may be DGA-generated".to_string();
        rule43.category = Some("malware".to_string());
        rule43.compile_pattern()?;
        rules.push(rule43);

        // Rule 44: IoT Device Compromise
        let mut rule44 = Rule::new(
            "1000044".to_string(),
            "IoT Device Compromise".to_string(),
            "Compromised IoT device detected".to_string(),
            "high".to_string(),
        );
        rule44.protocol = Some("tcp".to_string());
        rule44.destination_port = Some("23".to_string()); // Telnet
        rule44.payload_pattern = Some(r"(?i)(busybox|mirai|gafgyt|bashlite)".to_string());
        rule44.description = "Detects IoT malware indicators".to_string();
        rule44.category = Some("iot-security".to_string());
        rule44.compile_pattern()?;
        rules.push(rule44);

        // Rule 45: Cobalt Strike Beacon
        let mut rule45 = Rule::new(
            "1000045".to_string(),
            "Cobalt Strike Beacon".to_string(),
            "Cobalt Strike C2 beacon detected".to_string(),
            "critical".to_string(),
        );
        rule45.protocol = Some("https".to_string());
        rule45.destination_port = Some("443".to_string());
        rule45.payload_pattern = Some(r"(?i)(pipe|beacon|stager|cobaltstrike)".to_string());
        rule45.description = "Detects Cobalt Strike command and control beacons".to_string();
        rule45.category = Some("apt".to_string());
        rule45.compile_pattern()?;
        rules.push(rule45);

        // Rule 46: Container Escape Attempt
        let mut rule46 = Rule::new(
            "1000046".to_string(),
            "Container Escape".to_string(),
            "Container escape attempt detected".to_string(),
            "critical".to_string(),
        );
        rule46.protocol = Some("tcp".to_string());
        rule46.direction = Some("outbound".to_string());
        rule46.payload_pattern = Some(r"(?i)(/proc/self/cgroup|/sys/fs/cgroup|docker\.sock|kubernetes)".to_string());
        rule46.description = "Detects attempts to escape from containerized environments".to_string();
        rule46.category = Some("container-security".to_string());
        rule46.compile_pattern()?;
        rules.push(rule46);

        // Rule 47: Cryptojacking via WebAssembly
        let mut rule47 = Rule::new(
            "1000047".to_string(),
            "WebAssembly Cryptojacking".to_string(),
            "WebAssembly-based cryptojacking detected".to_string(),
            "high".to_string(),
        );
        rule47.protocol = Some("http".to_string());
        rule47.direction = Some("outbound".to_string());
        rule47.payload_pattern = Some(r"(?i)(\.wasm|webassembly|instantiate|coinhive|cryptonight)".to_string());
        rule47.description = "Detects WebAssembly-based cryptocurrency mining".to_string();
        rule47.category = Some("cryptojacking".to_string());
        rule47.compile_pattern()?;
        rules.push(rule47);

        // Rule 48: Supply Chain Attack Indicator
        let mut rule48 = Rule::new(
            "1000048".to_string(),
            "Supply Chain Attack".to_string(),
            "Supply chain attack indicator detected".to_string(),
            "critical".to_string(),
        );
        rule48.protocol = Some("https".to_string());
        rule48.direction = Some("outbound".to_string());
        rule48.payload_pattern = Some(r"(?i)(npm|pypi|rubygems|maven|nuget).*\.(tk|ml|ga|cf)".to_string());
        rule48.description = "Detects suspicious package repository access to unusual domains".to_string();
        rule48.category = Some("supply-chain".to_string());
        rule48.compile_pattern()?;
        rules.push(rule48);

        // Rule 49: Living off the Land (LOLBins)
        let mut rule49 = Rule::new(
            "1000049".to_string(),
            "LOLBins Usage".to_string(),
            "Living off the Land binaries usage detected".to_string(),
            "high".to_string(),
        );
        rule49.protocol = Some("tcp".to_string());
        rule49.direction = Some("any".to_string());
        rule49.payload_pattern = Some(r"(?i)(certutil|bitsadmin|mshta|rundll32|regsvr32|wmic|cscript|wscript).*(-urlcache|-transfer|javascript:|vbscript:)".to_string());
        rule49.description = "Detects misuse of legitimate Windows utilities".to_string();
        rule49.category = Some("lolbins".to_string());
        rule49.compile_pattern()?;
        rules.push(rule49);

        // Rule 50: AI Model Exfiltration
        let mut rule50 = Rule::new(
            "1000050".to_string(),
            "AI Model Theft".to_string(),
            "AI/ML model exfiltration detected".to_string(),
            "critical".to_string(),
        );
        rule50.protocol = Some("https".to_string());
        rule50.direction = Some("outbound".to_string());
        rule50.payload_pattern = Some(r"(?i)(\.h5|\.pb|\.pth|\.onnx|\.safetensors|model\.json|weights\.bin)".to_string());
        rule50.description = "Detects potential AI/ML model exfiltration".to_string();
        rule50.category = Some("data-theft".to_string());
        rule50.compile_pattern()?;
        rules.push(rule50);

        // Rule 51: Blockchain Smart Contract Attack
        let mut rule51 = Rule::new(
            "1000051".to_string(),
            "Smart Contract Attack".to_string(),
            "Blockchain smart contract attack detected".to_string(),
            "critical".to_string(),
        );
        rule51.protocol = Some("tcp".to_string());
        rule51.destination_port = Some("8545".to_string()); // Ethereum RPC
        rule51.payload_pattern = Some(r"(?i)(selfdestruct|delegatecall|reentrancy|overflow)".to_string());
        rule51.description = "Detects potential smart contract vulnerabilities exploitation".to_string();
        rule51.category = Some("blockchain-attack".to_string());
        rule51.compile_pattern()?;
        rules.push(rule51);

        // Rule 52: 5G Network Slicing Attack
        let mut rule52 = Rule::new(
            "1000052".to_string(),
            "5G Network Slicing Attack".to_string(),
            "5G network slicing attack detected".to_string(),
            "critical".to_string(),
        );
        rule52.protocol = Some("tcp".to_string());
        rule52.direction = Some("any".to_string());
        rule52.payload_pattern = Some(r"(?i)(slice|nssai|s-nssai|network\s+slice)".to_string());
        rule52.description = "Detects potential 5G network slicing security breaches".to_string();
        rule52.category = Some("5g-security".to_string());
        rule52.compile_pattern()?;
        rules.push(rule52);

        // Rule 53: Quantum-Safe Crypto Downgrade
        let mut rule53 = Rule::new(
            "1000053".to_string(),
            "Quantum Crypto Downgrade".to_string(),
            "Quantum-safe cryptography downgrade detected".to_string(),
            "critical".to_string(),
        );
        rule53.protocol = Some("https".to_string());
        rule53.direction = Some("any".to_string());
        rule53.payload_pattern = Some(r"(?i)(tls.*1\.[0-2]|ssl[23]|weak.*cipher|export.*cipher)".to_string());
        rule53.description = "Detects attempts to downgrade to quantum-vulnerable cryptography".to_string();
        rule53.category = Some("crypto-attack".to_string());
        rule53.compile_pattern()?;
        rules.push(rule53);

        // Rule 54: Deepfake Generation Traffic
        let mut rule54 = Rule::new(
            "1000054".to_string(),
            "Deepfake Generation".to_string(),
            "Deepfake generation traffic detected".to_string(),
            "high".to_string(),
        );
        rule54.protocol = Some("https".to_string());
        rule54.direction = Some("outbound".to_string());
        rule54.payload_pattern = Some(r"(?i)(deepfake|gan|generative|face.*swap|voice.*clone)".to_string());
        rule54.description = "Detects traffic patterns associated with deepfake generation".to_string();
        rule54.category = Some("ai-misuse".to_string());
        rule54.compile_pattern()?;
        rules.push(rule54);

        // Rule 55: Zero Trust Policy Violation
        let mut rule55 = Rule::new(
            "1000055".to_string(),
            "Zero Trust Violation".to_string(),
            "Zero Trust policy violation detected".to_string(),
            "high".to_string(),
        );
        rule55.protocol = Some("tcp".to_string());
        rule55.direction = Some("any".to_string());
        rule55.description = "Detects violations of Zero Trust network policies".to_string();
        rule55.category = Some("policy-violation".to_string());
        rules.push(rule55);

        // Rule 56: API Key Leakage
        let mut rule56 = Rule::new(
            "1000056".to_string(),
            "API Key Leakage".to_string(),
            "API key exposure detected".to_string(),
            "critical".to_string(),
        );
        rule56.protocol = Some("http".to_string());
        rule56.direction = Some("outbound".to_string());
        rule56.payload_pattern = Some(r"(?i)(api[_-]?key|apikey|access[_-]?token|bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*|aws[_-]?access[_-]?key[_-]?id)".to_string());
        rule56.description = "Detects potential API key or token leakage".to_string();
        rule56.category = Some("data-leakage".to_string());
        rule56.compile_pattern()?;
        rules.push(rule56);

        // Rule 57: Homograph Attack
        let mut rule57 = Rule::new(
            "1000057".to_string(),
            "Homograph Attack".to_string(),
            "IDN homograph attack detected".to_string(),
            "high".to_string(),
        );
        rule57.protocol = Some("dns".to_string());
        rule57.direction = Some("outbound".to_string());
        rule57.payload_pattern = Some(r"xn--".to_string()); // Punycode prefix
        rule57.description = "Detects potential internationalized domain name (IDN) homograph attacks".to_string();
        rule57.category = Some("phishing".to_string());
        rule57.compile_pattern()?;
        rules.push(rule57);

        // Rule 58: BIOS/UEFI Attack
        let mut rule58 = Rule::new(
            "1000058".to_string(),
            "BIOS/UEFI Attack".to_string(),
            "BIOS/UEFI level attack detected".to_string(),
            "critical".to_string(),
        );
        rule58.protocol = Some("tcp".to_string());
        rule58.direction = Some("any".to_string());
        rule58.payload_pattern = Some(r"(?i)(uefi|bios|bootkit|rootkit|spi.*flash)".to_string());
        rule58.description = "Detects potential BIOS/UEFI level attacks".to_string();
        rule58.category = Some("firmware-attack".to_string());
        rule58.compile_pattern()?;
        rules.push(rule58);

        // Rule 59: Hardware Implant Communication
        let mut rule59 = Rule::new(
            "1000059".to_string(),
            "Hardware Implant".to_string(),
            "Hardware implant communication detected".to_string(),
            "critical".to_string(),
        );
        rule59.protocol = Some("tcp".to_string());
        rule59.destination_port = Some("31337".to_string()); // Elite port
        rule59.direction = Some("outbound".to_string());
        rule59.description = "Detects potential hardware implant C2 communication".to_string();
        rule59.category = Some("hardware-attack".to_string());
        rules.push(rule59);

        // Rule 60: Memory Scraping Attack
        let mut rule60 = Rule::new(
            "1000060".to_string(),
            "Memory Scraping".to_string(),
            "Memory scraping attack detected".to_string(),
            "critical".to_string(),
        );
        rule60.protocol = Some("tcp".to_string());
        rule60.direction = Some("outbound".to_string());
        rule60.payload_pattern = Some(r"(?i)(credit.*card|cvv|track[12]|pan\d{13,19})".to_string());
        rule60.description = "Detects potential memory scraping for payment card data".to_string();
        rule60.category = Some("pos-malware".to_string());
        rule60.compile_pattern()?;
        rules.push(rule60);

        // Save default rules to files
        for rule in &rules {
            let rule_path = self.rules_dir.join(format!("{}.json", rule.id));
            if !rule_path.exists() {
                // Create parent directory if it doesn't exist
                if let Some(parent) = rule_path.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("Failed to create rule directory: {:?}", parent))?;
                    }
                }

                // Serialize rule to JSON
                let rule_json = serde_json::to_string_pretty(rule)
                    .context("Failed to serialize rule to JSON")?;

                // Write to file
                fs::write(&rule_path, rule_json)
                    .with_context(|| format!("Failed to write rule file: {:?}", rule_path))?;

                debug!("Created default rule file: {:?}", rule_path);
            }
        }

        Ok(rules)
    }
}