use async_trait::async_trait;
use std::sync::Arc;
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};

/// Resolver trait for real or mock DNS
#[async_trait]
pub trait ResolverTrait {
    async fn resolve_spf(&self, domain: &str) -> Option<String>;
    async fn resolve_dmarc(&self, domain: &str) -> Option<String>;
    /// Returns true if the domain exists (has A, AAAA, or MX records)
    async fn domain_exists(&self, domain: &str) -> bool;

    /// Check if domain has MX records
    async fn resolve_mx(&self, domain: &str) -> bool;
}

/// DNS resolver wrapper
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<TokioAsyncResolver>,
}

impl DnsResolver {
    pub fn new() -> anyhow::Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self {
            inner: Arc::new(resolver),
        })
    }

    /// Resolve TXT records for a domain
    pub async fn resolve_txt(&self, name: &str) -> Option<Vec<String>> {
        let response = self.inner.txt_lookup(name).await.ok()?;
        let mut records = Vec::new();
        for r in response.iter() {
            for txt in r.txt_data() {
                if let Ok(s) = std::str::from_utf8(txt) {
                    records.push(s.to_string());
                }
            }
        }
        Some(records)
    }
}

impl DnsResolver {
    /// Check if a domain exists (A/AAAA or MX)
    pub async fn check_domain(&self, domain: &str) -> bool {
        let ascii_domain = match idna::domain_to_ascii(domain) {
            Ok(d) => d,
            Err(_) => return false, // invalid IDN
        };

        // Query A/AAAA records
        let a_exists = match self.inner.lookup_ip(ascii_domain.clone()).await {
            Ok(ips) => ips.iter().next().is_some(),
            Err(_) => false,
        };

        // Query MX records
        let mx_exists = match self.inner.mx_lookup(ascii_domain).await {
            Ok(mx) => mx.iter().next().is_some(),
            Err(_) => false,
        };

        a_exists || mx_exists
    }
}

#[async_trait]
impl ResolverTrait for DnsResolver {
    async fn resolve_spf(&self, domain: &str) -> Option<String> {
        self.resolve_txt(domain)
            .await?
            .into_iter()
            .find(|s| s.starts_with("v=spf1"))
    }

    async fn resolve_dmarc(&self, domain: &str) -> Option<String> {
        let name = format!("_dmarc.{}", domain);
        self.resolve_txt(&name)
            .await?
            .into_iter()
            .find(|s| s.starts_with("v=DMARC1"))
    }

    async fn domain_exists(&self, domain: &str) -> bool {
        self.check_domain(domain).await
    }

    /// Check if domain has MX records
    async fn resolve_mx(&self, domain: &str) -> bool {
        match self.inner.mx_lookup(domain).await {
            Ok(mx_lookup) => mx_lookup.iter().next().is_some(),
            Err(_) => false,
        }
    }
}
