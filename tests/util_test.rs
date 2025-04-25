use veilstrike::utils::extract_domain_from_url;

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_url() {
        let test_cases = vec![
            ("https://www.google.com", Some("google.com")),
            ("http://sub.example.co.uk", Some("example.co.uk")),
            ("https://ftp.api.bbc.co.uk", Some("bbc.co.uk")),
            ("https://myapp.local", Some("myapp.local")), // local domains should pass through
            ("http://localhost", None),      // no TLD, should return as is
            ("invalid-url", None),                        // invalid URL, should return None
            ("https://食狮.中国", Some("xn--85x722f.xn--fiqs8s")),
            // unicode domains
            ("https://www.xn--85x722f.xn--55qx5d.cn", Some("xn--85x722f.xn--55qx5d.cn")),
        ];

        for (input, expected) in test_cases {
            let result = extract_domain_from_url(input);
            assert_eq!(result.as_deref(), expected, "Failed on input: {}", input);
        }
    }
}
