mod capture;
mod iface_names;
mod logger;
mod output;
mod protocols;

use capture::start_capture;
use iface_names::{extract_guid, get_friendly_names};
use logger::Logger;
use output::print_banner;
use pnet::datalink;
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::process;
use std::sync::Arc;

fn main() {
    print_banner();

    let args: Vec<String> = env::args().collect();

    // Заранее грузим дружественные имена из реестра
    let friendly = get_friendly_names();

    let interface_name = if args.len() >= 2 {
        args[1].clone()
    } else {
        select_interface_interactive(&friendly)
    };

    // Опциональный флаг --log <file.json>
    let log_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--log")
        .map(|w| w[1].clone());

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .unwrap_or_else(|| {
            eprintln!("\n❌  Interface '{}' not found.", interface_name);
            process::exit(1);
        });

    // Показываем красивое имя при старте захвата
    let display_name = pretty_name(&interface.name, &friendly);
    let logger = Arc::new(Logger::new(log_path));

    start_capture(interface, display_name, logger);
}

fn select_interface_interactive(friendly: &HashMap<String, String>) -> String {
    let interfaces = datalink::interfaces();

    if interfaces.is_empty() {
        eprintln!("❌  No network interfaces found.");
        process::exit(1);
    }

    println!("\n📡  Available network interfaces:\n");
    for (i, iface) in interfaces.iter().enumerate() {
        let fname = pretty_name(&iface.name, friendly);
        let flags = format_flags(iface);
        // Показываем: [N]  Wi-Fi  [UP]  (\Device\NPF_{...})
        println!(
            "  \x1b[1m[{}]\x1b[0m  \x1b[97m{:<20}\x1b[0m {}  \x1b[90m{}\x1b[0m",
            i + 1,
            fname,
            flags,
            iface.name,
        );
        for ip in &iface.ips {
            println!("        └─ \x1b[36m{}\x1b[0m", ip);
        }
    }
    println!();

    print!("Select interface number (or press Enter for [1]): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    let idx: usize = if input.is_empty() {
        1
    } else {
        input.parse().unwrap_or(1)
    };

    if idx == 0 || idx > interfaces.len() {
        eprintln!("❌  Invalid selection.");
        process::exit(1);
    }

    interfaces[idx - 1].name.clone()
}

/// Возвращает "Wi-Fi", "Ethernet" и т.п. или сокращённый GUID если имя не найдено
fn pretty_name(iface_name: &str, friendly: &HashMap<String, String>) -> String {
    if let Some(guid) = extract_guid(iface_name) {
        if let Some(name) = friendly.get(&guid) {
            return name.clone();
        }
    }
    // Fallback: если реестр не дал имя — показываем только GUID без префикса
    extract_guid(iface_name)
        .map(|g| format!("{{{}}}", &g[..8])) // только первый блок GUID
        .unwrap_or_else(|| iface_name.to_string())
}

fn format_flags(iface: &pnet::datalink::NetworkInterface) -> String {
    let mut flags = vec![];
    if iface.is_up() {
        flags.push("UP");
    }
    if iface.is_loopback() {
        flags.push("LOOP");
    }
    if flags.is_empty() {
        String::from("\x1b[90m[--]\x1b[0m")
    } else {
        format!("\x1b[32m[{}]\x1b[0m", flags.join("|"))
    }
}
