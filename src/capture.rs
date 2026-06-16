use crate::logger::Logger;
use crate::output::{print_flow, print_flow_update};
use crate::protocols::{FlowKey, FlowStats, PacketInfo, Protocol};
use chrono::Local;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Поток считается завершённым если не было пакетов N секунд
const FLOW_TIMEOUT_SECS: u64 = 5;
/// Как часто делаем flush устаревших потоков
const FLUSH_EVERY_N_PACKETS: u64 = 200;

pub fn start_capture(interface: NetworkInterface, display_name: String, logger: Arc<Logger>) {
    println!(
        "\n\x1b[1m🔍  Listening on:\x1b[0m \x1b[1;32m{}\x1b[0m  \x1b[90m{}\x1b[0m",
        display_name, interface.name
    );
    println!("    Protocols: HTTP · HTTPS · QUIC/HTTP3 · DNS · SSH · FTP · SMTP");
    println!("    Press \x1b[1mCtrl+C\x1b[0m to stop.\n");
    println!("{}", "─".repeat(72));

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("❌  Unsupported channel type.");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("❌  Failed to open channel: {}", e);
            eprintln!("    Run as Administrator / root?");
            process::exit(1);
        }
    };

    // Таблица активных потоков
    let mut flows: HashMap<FlowKey, (FlowStats, Instant)> = HashMap::new();
    let mut packet_counter: u64 = 0;

    loop {
        match rx.next() {
            Ok(frame) => {
                if let Some(pkt) = parse_ethernet(frame) {
                    let key = FlowKey::new(
                        pkt.src_ip,
                        pkt.src_port,
                        pkt.dst_ip,
                        pkt.dst_port,
                        pkt.protocol.clone(),
                    );

                    let now_str = pkt.timestamp.clone();
                    let now_inst = Instant::now();

                    let entry = flows.entry(key.clone()).or_insert_with(|| {
                        let stats = FlowStats {
                            first_seen: now_str.clone(),
                            last_seen: now_str.clone(),
                            packets: 0,
                            bytes: 0,
                            tls_version: None,
                            dns_query: None,
                            http_requests: Vec::new(),
                            src_ip: pkt.src_ip,
                            dst_ip: pkt.dst_ip,
                            src_port: pkt.src_port,
                            dst_port: pkt.dst_port,
                            protocol: pkt.protocol.clone(),
                            is_udp: pkt.is_udp,
                            printed: false,
                        };
                        (stats, now_inst)
                    });

                    let (stats, last_time) = entry;
                    stats.packets += 1;
                    stats.bytes += pkt.payload_len as u64;
                    stats.last_seen = now_str;
                    *last_time = now_inst;

                    if stats.tls_version.is_none() && pkt.tls_version.is_some() {
                        stats.tls_version = pkt.tls_version.clone();
                    }
                    if stats.dns_query.is_none() && pkt.dns_query.is_some() {
                        stats.dns_query = pkt.dns_query.clone();
                    }
                    if let Some(ref m) = pkt.http_method {
                        if !stats.http_requests.contains(m) && stats.http_requests.len() < 5 {
                            stats.http_requests.push(m.clone());
                        }
                    }

                    // Первый пакет потока — сразу печатаем
                    if !stats.printed {
                        print_flow(stats);
                        stats.printed = true;
                        logger.log_flow(stats);
                    } else {
                        // Обновляем счётчик на месте (in-place update)
                        print_flow_update(stats);
                    }

                    packet_counter += 1;
                    if packet_counter % FLUSH_EVERY_N_PACKETS == 0 {
                        flush_old_flows(&mut flows, &logger);
                    }
                }
            }
            Err(e) => {
                eprintln!("\x1b[31mRead error:\x1b[0m {}", e);
            }
        }
    }
}

/// Удаляем потоки у которых не было активности N секунд
fn flush_old_flows(flows: &mut HashMap<FlowKey, (FlowStats, Instant)>, _logger: &Arc<Logger>) {
    let timeout = Duration::from_secs(FLOW_TIMEOUT_SECS);
    flows.retain(|_, (_, last)| last.elapsed() < timeout);
}

// ── Парсинг пакетов ───────────────────────────────────────────────────────────

fn parse_ethernet(data: &[u8]) -> Option<PacketInfo> {
    let eth = EthernetPacket::new(data)?;
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(eth.payload()),
        EtherTypes::Ipv6 => parse_ipv6(eth.payload()),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<PacketInfo> {
    let ip = Ipv4Packet::new(data)?;
    let src = IpAddr::V4(ip.get_source());
    let dst = IpAddr::V4(ip.get_destination());
    match ip.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => parse_tcp(src, dst, ip.payload()),
        IpNextHeaderProtocols::Udp => parse_udp(src, dst, ip.payload()),
        _ => None,
    }
}

fn parse_ipv6(data: &[u8]) -> Option<PacketInfo> {
    let ip = Ipv6Packet::new(data)?;
    let src = IpAddr::V6(ip.get_source());
    let dst = IpAddr::V6(ip.get_destination());
    match ip.get_next_header() {
        IpNextHeaderProtocols::Tcp => parse_tcp(src, dst, ip.payload()),
        IpNextHeaderProtocols::Udp => parse_udp(src, dst, ip.payload()),
        _ => None,
    }
}

fn parse_tcp(src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Option<PacketInfo> {
    let tcp = TcpPacket::new(data)?;
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    if !Protocol::is_target(src_port, dst_port) {
        return None;
    }
    let payload = tcp.payload();
    let protocol = Protocol::from_ports_and_transport(src_port, dst_port, false);
    let tls_version = if matches!(protocol, Protocol::Https) {
        detect_tls_version(payload)
    } else {
        None
    };
    let http_method = if matches!(protocol, Protocol::Http) {
        detect_http_method(payload)
    } else {
        None
    };
    Some(PacketInfo {
        timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
        protocol,
        is_udp: false,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_len: payload.len(),
        payload_preview: payload[..payload.len().min(64)].to_vec(),
        tls_version,
        dns_query: None,
        http_method,
    })
}

fn parse_udp(src_ip: IpAddr, dst_ip: IpAddr, data: &[u8]) -> Option<PacketInfo> {
    let udp = UdpPacket::new(data)?;
    let src_port = udp.get_source();
    let dst_port = udp.get_destination();
    if !Protocol::is_target(src_port, dst_port) {
        return None;
    }
    let payload = udp.payload();
    let protocol = Protocol::from_ports_and_transport(src_port, dst_port, true);
    let dns_query = if matches!(protocol, Protocol::Dns) {
        parse_dns_query(payload)
    } else {
        None
    };
    Some(PacketInfo {
        timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
        protocol,
        is_udp: true,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_len: payload.len(),
        payload_preview: payload[..payload.len().min(64)].to_vec(),
        tls_version: None,
        dns_query,
        http_method: None,
    })
}

// ── Эвристики ─────────────────────────────────────────────────────────────────

fn detect_tls_version(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let ver = match (payload[1], payload[2]) {
        (0x03, 0x01) => "TLS 1.0",
        (0x03, 0x02) => "TLS 1.1",
        (0x03, 0x03) => "TLS 1.2/1.3",
        (0x03, 0x04) => "TLS 1.3",
        _ => return None,
    };
    Some(ver.to_string())
}

fn detect_http_method(payload: &[u8]) -> Option<String> {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let text = std::str::from_utf8(&payload[..payload.len().min(128)]).ok()?;
    for m in &methods {
        if text.starts_with(m) {
            // Берём только первую строку запроса
            let line = text.lines().next()?;
            // Укорачиваем если длинный URL
            if line.len() > 80 {
                return Some(format!("{}…", &line[..80]));
            }
            return Some(line.to_string());
        }
    }
    None
}

fn parse_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }
    // Флаг QR бит = 0 значит это запрос, 1 = ответ
    let is_query = (payload[2] & 0x80) == 0;
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= payload.len() {
            break;
        }
        let len = payload[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > payload.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&payload[pos..pos + len]).to_string());
        pos += len;
    }
    if labels.is_empty() {
        return None;
    }
    let domain = labels.join(".");
    if is_query {
        Some(format!("? {}", domain))
    } else {
        Some(format!("✓ {}", domain))
    }
}
