use crate::protocols::FlowStats;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

pub struct Logger {
    file: Option<Mutex<std::fs::File>>,
}

impl Logger {
    pub fn new(path: Option<String>) -> Self {
        let file = path.map(|p| {
            println!("📁  Logging to: \x1b[32m{}\x1b[0m", p);
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .unwrap_or_else(|e| {
                    eprintln!("❌  Cannot open log file '{}': {}", p, e);
                    std::process::exit(1);
                });
            Mutex::new(f)
        });
        Logger { file }
    }

    pub fn log_flow(&self, stats: &FlowStats) {
        let Some(ref mutex) = self.file else { return };

        let json = format!(
            "{{\
                \"first_seen\":\"{}\",\
                \"last_seen\":\"{}\",\
                \"proto\":\"{}\",\
                \"transport\":\"{}\",\
                \"src\":\"{}:{}\",\
                \"dst\":\"{}:{}\",\
                \"packets\":{},\
                \"bytes\":{}\
                {}{}{}\
            }}\n",
            stats.first_seen,
            stats.last_seen,
            stats.protocol.as_str(),
            if stats.is_udp { "UDP" } else { "TCP" },
            stats.src_ip,
            stats.src_port,
            stats.dst_ip,
            stats.dst_port,
            stats.packets,
            stats.bytes,
            stats
                .tls_version
                .as_ref()
                .map(|v| format!(",\"tls\":\"{}\"", v))
                .unwrap_or_default(),
            stats
                .dns_query
                .as_ref()
                .map(|v| format!(",\"dns_query\":\"{}\"", v))
                .unwrap_or_default(),
            stats
                .http_requests
                .first()
                .map(|v| format!(",\"http_request\":\"{}\"", v.replace('"', "\\\"")))
                .unwrap_or_default(),
        );

        if let Ok(mut f) = mutex.lock() {
            let _ = f.write_all(json.as_bytes());
        }
    }
}
