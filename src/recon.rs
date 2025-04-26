use std::fs::File;
use crate::target::{Target, TargetType};
use trust_dns_resolver::{TokioAsyncResolver, config::*};
use std::net::IpAddr;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::result::Result;
use tokio::sync::{Mutex, Semaphore};
use csv::{ReaderBuilder, Writer};

use crate::utils::{load_wordlist, write_recon_to_csv, extract_domain_from_url};


 // make sure this is imported

pub async fn run_recon(target: &Target) {
    match &target.target_type {
        TargetType::Url(domain) => {
            println!("🌐 Starting recon for domain: {}", domain);
            if let Some(clean_domain) = extract_domain_from_url(domain) {
                resolve_and_subdomains(&clean_domain).await;
            } else {
                eprintln!("❌ Failed to extract domain from URL.");
            }
        }
        TargetType::Ip(ip) => {
            println!("🔎 Recon for IP: {}", ip);
            // future: port scan, reverse DNS
        }
        TargetType::Repo(path) => {
            println!("📁 Analyzing local repo at {:?}", path);
            // future: secret scan, .env search
        }
    }
}


async fn resolve_and_subdomains(domain: &str) {
    println!("🔧 Resolving DNS...");
    let ips = resolve_dns(domain).await;
    for ip in &ips {
        println!("→ IP: {:?}", ip);
    }

    println!("\n🔍 Discovering subdomains...");

    // Since CSV writing happens inside discover_subdomains, no results are returned
    match discover_subdomains(domain).await {
        Ok(()) => {
            println!("\n📄 Subdomain results streamed to recon_output.csv");
        }
        Err(e) => {
            eprintln!("❌ Subdomain discovery failed: {}", e);
        }
    }
}


pub async fn resolve_dns(domain: &str) -> Result<Vec<IpAddr>, String> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );




    match resolver.lookup_ip(domain).await {
        Ok(lookup) => Ok(lookup.iter().collect()),
        Err(e) => Err(format!("DNS resolution failed for {}: {}", domain, e)),
    }
}



pub async fn discover_subdomains(domain: &str) -> std::io::Result<()> {
    let wordlist_path = "wordlists/subdomains.txt";

    let subnames = match load_wordlist(wordlist_path) {
        Ok(words) => words,
        Err(e) => {
            eprintln!("❌ Could not load wordlist: {}", e);
            return Ok(()); // continue flow
        }
    };

    let domain = Arc::new(domain.to_string());
    let semaphore = Arc::new(Semaphore::new(600));

    std::fs::create_dir_all("output")?;
    let file = File::create("output/recon_output.csv")?;
    let wtr = Arc::new(Mutex::new(Writer::from_writer(file)));

    // ✅ Write header once
    {
        let mut writer = wtr.lock().await;
        writer.write_record(&["Subdomain", "IP Addresses"])?;
        writer.flush()?;
    }

    let mut futures = FuturesUnordered::new();

    for sub in subnames {
        let domain = Arc::clone(&domain);
        let semaphore = Arc::clone(&semaphore);
        let wtr = Arc::clone(&wtr); // ✅ move writer into task

        futures.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let full = format!("{}.{}", sub, domain);

            match crate::recon::resolve_dns(&full).await {
                Ok(ips) if !ips.is_empty() => {
                    println!("✅ Found: {} → {:?}", full, ips);

                    let ip_list = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");

                    let mut writer = wtr.lock().await;
                    if let Err(e) = writer.write_record(&[&full, &ip_list]) {
                        eprintln!("❌ Failed to write to CSV: {}", e);
                    }
                    let _ = writer.flush();

                    Some((full, ips))
                }
                _ => None,
            }
        }));
    }

    let mut count = 0;
    while let Some(result) = futures.next().await {
        if let Ok(Some((_sub, _ips))) = result {
            count += 1;
        }
    }

    println!("\n✅ Total subdomains found: {}", count);

    // ✅ Final CSV validation
    let file = File::open("output/recon_output.csv")?;
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(file);

    let expected_field_count = 2;
    for (i, result) in reader.records().enumerate() {
        match result {
            Ok(record) => {
                if record.len() != expected_field_count {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("CSV validation error: record {} has {} fields", i + 2, record.len()),
                    ));
                }
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("CSV parsing error at record {}: {}", i + 2, e),
                ));
            }
        }
    }

    Ok(())
}
