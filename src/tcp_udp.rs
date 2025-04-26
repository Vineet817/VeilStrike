use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use csv::Reader;
use std::time::Duration;

// TCP scanner
async fn scan_tcp(ip: &str, port: u16) -> bool {
    let addr = format!("{}:{}", ip, port);
    tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(&addr))
        .await
        .is_ok()
}

// Check if a file exists for an IP
fn port_file_exists(ip: &str) -> bool {
    Path::new(&format!("Ports/{}.txt", ip)).exists()
}

// Save open ports into Ports/<ip>.txt
fn save_ports_to_file(ip: &str, ports: &[u16]) -> std::io::Result<()> {
    fs::create_dir_all("Ports")?;
    let path = format!("Ports/{}.txt", ip);
    let mut file = File::create(path)?;

    for port in ports {
        writeln!(file, "{}", port)?;
    }

    Ok(())
}

// Extract IPs from CSV
fn extract_ips_from_csv(path: &str) -> std::io::Result<HashSet<String>> {
    let mut reader = Reader::from_path(path)?;
    let mut ips = HashSet::new();

    for result in reader.records() {
        let record = result?;
        if record.len() >= 2 {
            let ip_list = record[1].split(',').map(str::trim);
            for ip in ip_list {
                if !ip.is_empty() {
                    ips.insert(ip.to_string());
                }
            }
        }
    }

    Ok(ips)
}

// Run the full scanner based on CSV
pub async fn run_conditional_port_scans(csv_path: &str) {
    let ips = match extract_ips_from_csv(csv_path) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("❌ Failed to read CSV: {}", e);
            return;
        }
    };

    for ip in ips {
        if port_file_exists(&ip) {
            println!("⚠️ Skipping {} — already scanned.", ip);
            continue;
        }

        println!("🔍 Scanning {}...", ip);
        scan_and_save_ports(&ip).await;
    }
}

// Scans all ports and saves if any are found
async fn scan_and_save_ports(ip: &str) {
    const MAX_CONCURRENCY: usize = 1000;
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENCY));
    let mut tasks = FuturesUnordered::new();
    let open_ports = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    for port in 1u16..=65535 {
        let ip = ip.to_string();
        let sem = semaphore.clone();
        let ports = open_ports.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if scan_tcp(&ip, port).await {
                let mut ports = ports.lock().await;
                ports.push(port);
            }
        }));
    }

    while let Some(_) = tasks.next().await {}

    let ports = open_ports.lock().await;
    if !ports.is_empty() {
        if let Err(e) = save_ports_to_file(ip, &ports) {
            eprintln!("❌ Failed to save ports for {}: {}", ip, e);
        } else {
            println!("✅ Saved {} open ports for {}", ports.len(), ip);
        }
    } else {
        println!("ℹ️ No open ports found for {}", ip);
    }
}
