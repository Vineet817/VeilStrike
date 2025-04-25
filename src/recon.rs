use crate::target::{Target, TargetType};
use trust_dns_resolver::{TokioAsyncResolver, config::*};
use std::net::IpAddr;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::result::Result;
use tokio::sync::Semaphore;


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

use std::fs::OpenOptions;
use csv::Writer;
pub async fn discover_subdomains(domain: &str) -> std::io::Result<()> {
    let wordlist_path = "wordlists/subdomains.txt";

    let subnames = match crate::utils::load_wordlist(wordlist_path) {
        Ok(words) => words,
        Err(e) => {
            eprintln!("❌ Could not load wordlist: {}", e);
            return Ok(()); // continue flow
        }
    };

    let domain = Arc::new(domain.to_string());
    let semaphore = Arc::new(Semaphore::new(600));

    // Open file and prepare writer
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("output/recon_output.csv")?;

    let mut wtr = Writer::from_writer(file);

    // Optionally write header
    wtr.write_record(&["Subdomain", "IP Addresses"])?;

    let mut futures = FuturesUnordered::new();

    for sub in subnames {
        let domain = Arc::clone(&domain);
        let semaphore = Arc::clone(&semaphore);
        std::fs::create_dir_all("output")?;
        let writer_path = "output/recon_output.csv".to_string();

        futures.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let full = format!("{}.{}", sub, domain);

            match crate::recon::resolve_dns(&full).await {
                Ok(ips) if !ips.is_empty() => {
                    // ✅ Print to terminal
                    println!("✅ Found: {} → {:?}", full, ips);

                    // ✅ Append to CSV
                    let mut wtr = csv::Writer::from_writer(
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&writer_path)
                            .expect("Failed to open CSV")
                    );

                    let ip_list = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
                    let _ = wtr.write_record(&[&full, &ip_list]);
                    let _ = wtr.flush();

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
    Ok(())
}
