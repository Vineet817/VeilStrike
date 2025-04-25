use std::fs::File;
use std::collections::HashSet;
use csv::Reader;
use lazy_static::lazy_static;
use std::sync::Mutex;


pub fn extract_unique_ips(csv_path: &str) -> std::io::Result<HashSet<String>> {
    let mut reader = Reader::from_path(csv_path)?;
    let mut ips = HashSet::new();

    for result in reader.records() {
        let record = result?;
        if record.len() < 2 {
            continue;
        }
        let ip_list = record[1].split(',').map(str::trim);
        for ip in ip_list {
            if !ip.is_empty() {
                ips.insert(ip.to_string());
            }
        }
    }

    Ok(ips)
}
use tokio::net::TcpStream;
use std::time::Duration;

pub async fn scan_tcp(ip: &str, port: u16) -> bool {
    let addr = format!("{}:{}", ip, port);
    tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(&addr))
        .await
        .is_ok()
}
use tokio::net::UdpSocket;
use std::fs::{ OpenOptions};
pub async fn scan_udp(ip: &str, port: u16) -> bool {
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let addr = format!("{}:{}", ip, port);
    let _ = socket.send_to(b"ping", &addr).await;

    let mut buf = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await.is_ok()
}
use tokio::sync::Semaphore;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;





pub async fn scan_all_ports(ip: &str) {
    const MAX_CONCURRENCY: usize = 1000;
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENCY));
    let mut tasks = FuturesUnordered::new();

    for port in 1u16..=65535 {
        let ip = ip.to_string();
        let sem = semaphore.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if scan_tcp(&ip, port).await {
                println!("🟢 TCP Open → {}:{}", ip, port);
                lazy_static::lazy_static! {
    static ref FILE: Mutex<File> = Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("open_ports.csv")
            .expect("Failed to open CSV")
    );
}
            }
        }));
    }

    while let Some(_) = tasks.next().await {}
}

const ALL_PORTS: std::ops::RangeInclusive<u16> = 1..=65535;

use std::path::Path;

pub async fn run_port_scans(csv_path: &str) {
    if !Path::new(csv_path).exists() {
        eprintln!("❌ CSV file '{}' not found. Did subdomain recon run?", csv_path);
        return;
    }

    let ips = extract_unique_ips(csv_path).expect("❌ Failed to parse CSV");

    for ip in ips {
        println!("\n🌐 Scanning IP: {}", ip);
        scan_all_ports(&ip).await;
    }
}


