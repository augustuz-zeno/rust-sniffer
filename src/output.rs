use crate::protocols::FlowStats;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[90m";
const UP1: &str = "\x1b[1A"; // курсор вверх на 1 строку
const CLR: &str = "\x1b[2K"; // очистить текущую строку

pub fn print_banner() {
    println!("{}", BOLD);
    println!("  ██████╗ ██╗   ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ ");
    println!("  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗");
    println!("  ██████╔╝██║   ██║███████╗   ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝");
    println!("  ██╔══██╗██║   ██║╚════██║   ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗");
    println!("  ██║  ██║╚██████╔╝███████║   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║");
    println!("  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝");
    println!("{}", RESET);
    println!(
        "  {}Network packet sniffer — HTTP · HTTPS · QUIC · DNS · SSH · FTP · SMTP{}",
        DIM, RESET
    );
}

/// Рисует одну строку потока (вызывается один раз при первом пакете)
pub fn print_flow(stats: &FlowStats) {
    println!("{}", flow_line(stats));
}

/// Обновляет последнюю строку потока на месте (in-place)
pub fn print_flow_update(stats: &FlowStats) {
    // Поднимаемся на строку вверх, очищаем её и перерисовываем
    print!("{}{}{}\r", UP1, CLR, flow_line(stats));
    // Переходим обратно вниз чтобы следующий println не затёр
    println!();
}

fn flow_line(stats: &FlowStats) -> String {
    let color = stats.protocol.color_code();
    let transport = if stats.is_udp { "UDP" } else { "TCP" };

    // Нормализуем направление: показываем от клиента к серверу
    // (клиент — тот у кого высокий эфемерный порт)
    let (src, sport, dst, dport) = if stats.src_port > stats.dst_port {
        (stats.src_ip, stats.src_port, stats.dst_ip, stats.dst_port)
    } else {
        (stats.dst_ip, stats.dst_port, stats.src_ip, stats.src_port)
    };

    // Метка протокола
    let proto_tag = format!(
        "{}{}[{:<10}]{} {}{}{} ",
        BOLD,
        color,
        stats.protocol.as_str(),
        RESET,
        DIM,
        transport,
        RESET
    );

    // Статистика
    let stats_tag = format!(
        "{}{}pkts:{} {}bytes:{}{}",
        DIM,
        BOLD,
        stats.packets,
        BOLD,
        fmt_bytes(stats.bytes),
        RESET,
    );

    // Дополнительная информация
    let mut extra = String::new();
    if let Some(ref tls) = stats.tls_version {
        extra = format!("  {}[{}]{}", color, tls, RESET);
    }
    if let Some(ref dns) = stats.dns_query {
        extra = format!("  {}{}{}", color, dns, RESET);
    }
    if let Some(first_req) = stats.http_requests.first() {
        extra = format!("  {}{}{}", color, first_req, RESET);
    }

    format!(
        "{}{}{} {}{}:{} → {}{}:{}{}  {}  {}{}",
        DIM,
        stats.first_seen,
        RESET,
        proto_tag,
        src,
        sport,
        dst,
        dport,
        DIM,
        RESET,
        stats_tag,
        extra,
        "",
    )
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{}B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{:.1}MB", b as f64 / (1024.0 * 1024.0))
    }
}
