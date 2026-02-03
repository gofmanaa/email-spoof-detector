use idna::domain_to_ascii;
use mailparse::{MailHeaderMap, parse_mail};

/// Parsed email with extracted headers
#[derive(Debug)]
pub struct EmailParsed {
    pub from: Option<String>,
    pub return_path: Option<String>,
    pub auth_results: Option<String>,
    pub dkim_present: bool,
}

pub fn parse_email(raw: &[u8]) -> anyhow::Result<EmailParsed> {
    let parsed = parse_mail(raw)?;
    let from_header = parsed.headers.get_first_value("From");
    let return_path = parsed.headers.get_first_value("Return-Path");
    let auth_results = parsed.headers.get_first_value("Authentication-Results");
    let dkim_present = parsed.headers.get_first_value("DKIM-Signature").is_some();

    Ok(EmailParsed {
        from: from_header,
        return_path,
        auth_results,
        dkim_present,
    })
}

/// Extracts domain from an email address, normalized to ASCII
pub fn extract_domain(from: Option<&str>) -> Option<String> {
    from.and_then(|f| {
        f.split('@').nth(1).map(|s| {
            let s = s.trim().trim_end_matches('>').trim();
            domain_to_ascii(s).unwrap_or(s.to_string())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::super::parse::{extract_domain, parse_email};

    #[test]
    fn test_extract_domain_basic() {
        let email = Some("user@example.com");
        let domain = extract_domain(email);
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_domain_with_angle_brackets() {
        let email = Some("<user@sub.example.org>");
        let domain = extract_domain(email);
        assert_eq!(domain, Some("sub.example.org".to_string()));
    }

    #[test]
    fn test_extract_domain_none() {
        let email: Option<&str> = None;
        let domain = extract_domain(email);
        assert_eq!(domain, None);
    }

    #[tokio::test]
    async fn test_parse_email_simple() {
        let raw = b"From: test@example.com\r\nReturn-Path: <bounce@example.com>\r\n";
        let parsed = parse_email(raw).unwrap();
        assert_eq!(parsed.from.unwrap(), "test@example.com");
        assert_eq!(parsed.return_path.unwrap(), "<bounce@example.com>");
        assert!(!parsed.dkim_present);
    }

    #[tokio::test]
    async fn test_parse_email_with_dkim() {
        let raw = b"From: test@example.com\r\nDKIM-Signature: v=1; a=rsa-sha256;\r\n";
        let parsed = parse_email(raw).unwrap();
        assert!(parsed.dkim_present);
    }
}
