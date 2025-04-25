use std::path::PathBuf;

#[allow(dead_code)]
#[derive(Debug)]
pub enum TargetType {
    Url(String),
    Ip(String),
    Repo(PathBuf),
}

#[derive(Debug)]
pub struct Target {
    pub target_type: TargetType,
}

impl Target {
    pub fn new_from_args(url: Option<String>, ip: Option<String>, repo: Option<PathBuf>) -> Result<Self, String> {
        match (url, ip, repo) {
            (Some(u), None, None) => {
                if u.starts_with("http") {
                    Ok(Target { target_type: TargetType::Url(u) })
                } else {
                    Err("Invalid URL".to_string())
                }
            }
            (None, Some(i), None) => {
                if i.parse::<std::net::IpAddr>().is_ok() {
                    Ok(Target { target_type: TargetType::Ip(i) })
                } else {
                    Err("Invalid IP address".to_string())
                }
            }
            (None, None, Some(p)) => {
                if p.exists() && p.is_dir() {
                    Ok(Target { target_type: TargetType::Repo(p) })
                } else {
                    Err("Invalid or non-existent repo path".to_string())
                }
            }
            _ => Err("Provide exactly one of --url, --ip, or --repo".to_string()),
        }
    }
}
