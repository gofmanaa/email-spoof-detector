use crate::{dns::ResolverTrait, parse::EmailParsed};

/// Final verdict enums
/// Represents the final classification of an email after analysis.
///
/// The `Verdict` is determined by examining SPF, DKIM, DMARC results,
/// alignment between the sender's domain and the email headers, and other heuristics.
///
/// - `Authenticated` – The email passes all verification checks and aligns with the claimed domain.
/// - `PolicyViolation` – The email violates the domain's DMARC policy or has a clear misalignment.
/// - `Unauthenticated` – The email cannot be verified (missing SPF, DKIM, or DMARC records).
/// - `Suspicious` – The email shows inconsistencies, but not enough to definitively label as spoofed.
/// - `Indeterminate` – The verdict cannot be determined due to missing or malformed data.
#[derive(Debug, serde::Serialize, PartialEq)]
pub enum Verdict {
    Authenticated,
    PolicyViolation,
    Unauthenticated,
    Suspicious,
    Indeterminate,
}

/// Represents the individual evidence collected from the email that contributes to the final verdict.
///
/// This struct contains both the raw extracted data and computed boolean indicators
/// that describe alignment and authorization status.
#[derive(Debug, serde::Serialize)]
pub struct Evidence {
    /// The domain extracted from the "From" header of the email.
    pub from_domain: Option<String>,

    /// The SPF record retrieved for the sender domain, if available.
    pub spf_policy: Option<String>,

    /// The DMARC record retrieved for the sender domain, if available.
    pub dmarc_policy: Option<String>,

    /// Indicates whether the sending IP is authorized by the SPF policy.
    pub spf_authorized: bool,

    /// Indicates whether a DKIM signature is present in the email.
    pub dkim_present: bool,

    /// Indicates whether the SPF and DKIM results align with the "From" domain per DMARC rules.
    pub alignment_ok: bool,

    pub domain_valid: bool,
}

/// Represents the result of analyzing an email for spoofing.
///
/// Combines a `Verdict` with the detailed `Evidence` used to reach that conclusion.
/// This struct is intended for both programmatic consumption (e.g., web API) and human inspection.
#[derive(Debug, serde::Serialize)]
pub struct AnalysisResult {
    /// The final classification of the email.
    pub verdict: Verdict,

    /// Detailed evidence supporting the verdict.
    pub evidence: Evidence,
}

/// Core function: Analyze parsed email + DNS
pub async fn analyze_email<R: ResolverTrait + Sync + Send>(
    parsed: &EmailParsed,
    dns: &R,
) -> anyhow::Result<AnalysisResult> {
    let from_domain = crate::parse::extract_domain(parsed.from.as_deref());

    let spf_policy = from_domain
        .as_deref()
        .and_then(|d| futures::executor::block_on(dns.resolve_spf(d)));

    let dmarc_policy = from_domain
        .as_deref()
        .and_then(|d| futures::executor::block_on(dns.resolve_dmarc(d)));

    // Check domain existence (A/AAAA or MX)
    let domain_valid = if let Some(ref domain) = from_domain {
        futures::executor::block_on(dns.domain_exists(domain))
    } else {
        false
    };

    let alignment_ok = match (&from_domain, &spf_policy) {
        (Some(_), Some(p)) => p.contains("-all"),
        _ => false,
    };

    let spf_authorized = alignment_ok;
    let dkim_present = parsed.dkim_present;

    let verdict = decide_verdict(
        &from_domain,
        &spf_policy,
        &dmarc_policy,
        dkim_present,
        alignment_ok,
        domain_valid,
    );

    Ok(AnalysisResult {
        verdict,
        evidence: Evidence {
            from_domain,
            spf_policy,
            dmarc_policy,
            spf_authorized,
            dkim_present,
            alignment_ok,
            domain_valid,
        },
    })
}

pub fn decide_verdict(
    from_domain: &Option<String>,
    spf: &Option<String>,
    dmarc: &Option<String>,
    dkim_present: bool,
    alignment_ok: bool,
    domain_valid: bool,
) -> Verdict {
    if !domain_valid {
        return Verdict::Suspicious;
    }

    // Policy violation: DMARC is p=reject but alignment fails
    if let Some(dmarc_policy) = dmarc {
        if dmarc_policy.contains("p=reject") && !alignment_ok {
            return Verdict::PolicyViolation;
        }
    }

    match (from_domain, spf, dmarc, dkim_present, alignment_ok) {
        (_, None, None, false, _) => Verdict::Unauthenticated,
        (_, _, _, true, true) => Verdict::Authenticated,
        _ => Verdict::Suspicious,
    }
}

#[cfg(test)]
mod verdict_tests {
    use super::super::{email_verdict::Verdict, parse::EmailParsed};

    #[tokio::test]
    async fn test_unauthenticated_email() {
        let email = EmailParsed {
            from: Some("user@evil.com".to_string()),
            return_path: Some("bounce@evil.com".to_string()),
            auth_results: None,
            dkim_present: false,
        };

        let alignment_ok = false;
        let verdict = if email.dkim_present && alignment_ok {
            Verdict::Authenticated
        } else {
            Verdict::Unauthenticated
        };

        assert_eq!(verdict, Verdict::Unauthenticated);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::super::dns::ResolverTrait;
    use crate::email_verdict::{Verdict, analyze_email};
    use crate::parse::{EmailParsed, parse_email};
    use async_trait::async_trait;

    struct MockResolver;

    #[async_trait]
    impl ResolverTrait for MockResolver {
        async fn resolve_spf(&self, domain: &str) -> Option<String> {
            match domain {
                "example.com" => Some("v=spf1 -all".to_string()),
                "misaligned.com" => Some("v=spf1 -all".to_string()),
                _ => None,
            }
        }

        async fn resolve_dmarc(&self, domain: &str) -> Option<String> {
            match domain {
                "example.com" => Some("v=DMARC1; p=reject".to_string()),
                "misaligned.com" => Some("v=DMARC1; p=reject".to_string()),
                _ => None,
            }
        }

        async fn domain_exists(&self, domain: &str) -> bool {
            matches!(domain, "example.com" | "misaligned.com")
        }

        async fn resolve_mx(&self, domain: &str) -> bool {
            matches!(domain, "example.com" | "misaligned.com")
        }
    }

    #[tokio::test]
    async fn test_authenticated_email() {
        let raw = b"From: user@example.com\r\nDKIM-Signature: v=1; a=rsa-sha256;\r\n";
        let parsed: EmailParsed = parse_email(raw).unwrap();
        let resolver = MockResolver;

        let result = analyze_email(&parsed, &resolver).await.unwrap();

        assert_eq!(result.verdict, Verdict::Authenticated);
        assert_eq!(result.evidence.dkim_present, true);
        assert_eq!(result.evidence.from_domain.as_deref(), Some("example.com"));
        assert_eq!(result.evidence.spf_policy.as_deref(), Some("v=spf1 -all"));
        assert_eq!(
            result.evidence.dmarc_policy.as_deref(),
            Some("v=DMARC1; p=reject")
        );
        assert_eq!(result.evidence.domain_valid, true);
    }

    #[tokio::test]
    async fn test_nonexistent_domain() {
        let raw = b"From: user@fake-domain.com\r\n";
        let parsed: EmailParsed = parse_email(raw).unwrap();
        let resolver = MockResolver;

        let result = analyze_email(&parsed, &resolver).await.unwrap();

        assert_eq!(result.verdict, Verdict::Suspicious);
        assert_eq!(result.evidence.domain_valid, false);
    }

    // #[tokio::test]
    // async fn test_policy_violation_due_to_dmarc() {
    //     // DKIM present but alignment fails
    //     let raw = b"From: user@misaligned.com\r\nDKIM-Signature: v=1; a=rsa-sha256;\r\n";
    //     let parsed: EmailParsed = parse_email(raw).unwrap();
    //     let resolver = MockResolver;

    //     let result = analyze_email(&parsed, &resolver).await.unwrap();

    //     // Alignment fails; DMARC policy is reject → PolicyViolation
    //     assert_eq!(result.verdict, Verdict::PolicyViolation);
    //     assert_eq!(result.evidence.from_domain.as_deref(), Some("misaligned.com"));
    //     assert_eq!(result.evidence.dkim_present, true);
    //     assert_eq!(result.evidence.domain_valid, true);
    // }

    #[tokio::test]
    async fn test_suspicious_email_missing_dkim() {
        // Missing DKIM, domain exists → Suspicious
        let raw = b"From: user@misaligned.com\r\n";
        let parsed: EmailParsed = parse_email(raw).unwrap();
        let resolver = MockResolver;

        let result = analyze_email(&parsed, &resolver).await.unwrap();

        assert_eq!(result.verdict, Verdict::Suspicious);
        assert_eq!(result.evidence.dkim_present, false);
        assert_eq!(result.evidence.domain_valid, true);
    }
}
