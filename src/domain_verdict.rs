use crate::dns::ResolverTrait;
use crate::DnsResolver;
use std::future::Future;
use std::pin::Pin;

const MAX_SPF_DEPTH: usize = 10;

#[derive(Debug, serde::Serialize)]
pub enum DomainVerdict {
    Strong,
    Medium,
    Weak,
    Invalid,
}

/// Structured evaluation of SPF
#[derive(Debug, Default, serde::Serialize)]
pub struct SpfEvaluation {
    pub has_strict_all: bool,
    pub has_soft_all: bool,
}

/// Structured SPF resolver entrypoint
pub async fn resolve_spf_structured(
    resolver: &DnsResolver,
    domain: &str,
    depth: usize,
) -> SpfEvaluation {
    resolve_spf_structured_inner(resolver, domain, depth).await
}

/// Boxed recursive SPF resolver
fn resolve_spf_structured_inner<'a>(
    resolver: &'a DnsResolver,
    domain: &'a str,
    depth: usize,
) -> Pin<Box<dyn Future<Output = SpfEvaluation> + Send + 'a>> {
    Box::pin(async move {
        if depth >= MAX_SPF_DEPTH {
            // Depth limit reached, stop recursion safely
            return SpfEvaluation::default();
        }

        let spf_txt = match resolver.resolve_spf(domain).await {
            Some(txt) => txt,
            None => return SpfEvaluation::default(),
        };

        let mut eval = SpfEvaluation::default();

        for part in spf_txt.split_whitespace() {
            match part {
                "-all" => eval.has_strict_all = true,
                "~all" | "?all" => eval.has_soft_all = true,
                _ => {}
            }

            if let Some(include_domain) = part.strip_prefix("include:") {
                let child = resolve_spf_structured_inner(
                    resolver,
                    include_domain,
                    depth + 1,
                )
                    .await;

                eval.has_strict_all |= child.has_strict_all;
                eval.has_soft_all |= child.has_soft_all;
            }

            // Fast exit if strongest signals are already found
            if eval.has_strict_all && eval.has_soft_all {
                break;
            }
        }

        eval
    })
}

/// Compute verdict using structured SPF + DMARC
pub fn calculate_domain_verdict(
    exists: bool,
    spf_eval: &SpfEvaluation,
    dmarc: Option<&str>,
) -> DomainVerdict {
    if !exists {
        return DomainVerdict::Invalid;
    }

    let dmarc_policy = dmarc.unwrap_or("");
    let dmarc_strong = dmarc_policy.contains("p=reject");
    let dmarc_medium = dmarc_policy.contains("p=quarantine");

    match (
        spf_eval.has_strict_all,
        spf_eval.has_soft_all,
        dmarc_strong,
        dmarc_medium,
    ) {
        (true, _, true, _) => DomainVerdict::Strong,
        (_, _, true, _) => DomainVerdict::Medium,
        (_, true, _, _) => DomainVerdict::Medium,
        _ => DomainVerdict::Weak,
    }
}


/// Check DKIM selector presence
pub async fn resolve_dkim(
    resolver: &DnsResolver,
    domain: &str,
) -> bool {
    // Common selectors; intentionally small allowlist
    const SELECTORS: [&str; 4] = ["default", "google", "selector1", "selector2"];

    for selector in SELECTORS {
        let name = format!("{}._domainkey.{}", selector, domain);
        if resolver.resolve_txt(&name).await.is_some() {
            return true ;
        }
    }

    false
}

