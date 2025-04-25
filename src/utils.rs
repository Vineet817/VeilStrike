use std::fs::File;
use std::io::{BufRead, BufReader, Result};
use csv::Writer;
use std::net::IpAddr;
use url::Url;
use psl::domain;

/// Loads a wordlist from file into a vector of strings.
pub fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut words = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            words.push(trimmed.to_string());
        }
    }

    Ok(words)
}

/// Extracts the root domain from a full URL using PSL.
pub fn extract_domain_from_url(full_url: &str) -> Option<String> {
    let parsed_url = Url::parse(full_url).ok()?;
    let host = parsed_url.host_str()?;
    domain(host.as_bytes()).map(|d| String::from_utf8_lossy(d.as_bytes()).to_string())
}

/// Saves recon results to a CSV file.
pub fn write_recon_to_csv(results: &[(String, Vec<IpAddr>)], path: &str) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut wtr = Writer::from_writer(file);

    wtr.write_record(&["Subdomain", "IP Addresses"])?;

    for (subdomain, ips) in results {
        let ip_list = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
        wtr.write_record(&[subdomain, &ip_list])?;
    }

    wtr.flush()?;
    Ok(())
}
