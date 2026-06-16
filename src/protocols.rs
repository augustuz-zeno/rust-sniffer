use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Https,
    Quic, // HTTP/3 — UDP:443
    Dns,
    Ssh,
    Ftp,
    Smtp,
    Unknown,
}

impl Protocol {
    /// Определяет протокол с учётом транспорта (TCP vs UDP)
    pub fn from_ports_and_transport(src: u16, dst: u16, is_udp: bool) -> Self {
        match (src, dst) {
            (80, _) | (_, 80) => Protocol::Http,
            // UDP:443 — это QUIC/HTTP3, TCP:443 — классический TLS
            (443, _) | (_, 443) => {
                if is_udp {
                    Protocol::Quic
                } else {
                    Protocol::Https
                }
            }
            (53, _) | (_, 53) => Protocol::Dns,
            (22, _) | (_, 22) => Protocol::Ssh,
            (20, _) | (_, 20) | (21, _) | (_, 21) => Protocol::Ftp,
            (25, _) | (_, 25) | (587, _) | (_, 587) | (465, _) | (_, 465) => Protocol::Smtp,
            _ => Protocol::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "HTTP",
            Protocol::Https => "HTTPS",
            Protocol::Quic => "QUIC/HTTP3",
            Protocol::Dns => "DNS",
            Protocol::Ssh => "SSH",
            Protocol::Ftp => "FTP",
            Protocol::Smtp => "SMTP",
            Protocol::Unknown => "???",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            Protocol::Http => "\x1b[33m",    // жёлтый
            Protocol::Https => "\x1b[32m",   // зелёный
            Protocol::Quic => "\x1b[96m",    // ярко-голубой
            Protocol::Dns => "\x1b[36m",     // голубой
            Protocol::Ssh => "\x1b[35m",     // фиолетовый
            Protocol::Ftp => "\x1b[34m",     // синий
            Protocol::Smtp => "\x1b[31m",    // красный
            Protocol::Unknown => "\x1b[90m", // серый
        }
    }

    pub fn is_target(src: u16, dst: u16) -> bool {
        matches!(
            (src, dst),
            (80, _)
                | (_, 80)
                | (443, _)
                | (_, 443)
                | (53, _)
                | (_, 53)
                | (22, _)
                | (_, 22)
                | (20, _)
                | (_, 20)
                | (21, _)
                | (_, 21)
                | (25, _)
                | (_, 25)
                | (587, _)
                | (_, 587)
                | (465, _)
                | (_, 465)
        )
    }
}

/// Ключ потока — уникален для каждого соединения (нормализован: меньший IP/порт первым)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub ip_a: IpAddr,
    pub port_a: u16,
    pub ip_b: IpAddr,
    pub port_b: u16,
    pub protocol: Protocol,
}

impl FlowKey {
    pub fn new(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, proto: Protocol) -> Self {
        // Нормализуем направление чтобы A→B и B→A попадали в один поток
        if (src, sport) < (dst, dport) {
            FlowKey {
                ip_a: src,
                port_a: sport,
                ip_b: dst,
                port_b: dport,
                protocol: proto,
            }
        } else {
            FlowKey {
                ip_a: dst,
                port_a: dport,
                ip_b: src,
                port_b: sport,
                protocol: proto,
            }
        }
    }
}

/// Агрегированная статистика одного потока
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub first_seen: String,
    pub last_seen: String,
    pub packets: u64,
    pub bytes: u64,
    pub tls_version: Option<String>,
    pub dns_query: Option<String>,
    pub http_requests: Vec<String>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub is_udp: bool,
    /// Флаг: поток уже был выведен хотя бы раз (для live-update)
    pub printed: bool,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: String,
    pub protocol: Protocol,
    pub is_udp: bool,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: usize,
    pub payload_preview: Vec<u8>,
    pub tls_version: Option<String>,
    pub dns_query: Option<String>,
    pub http_method: Option<String>,
}
