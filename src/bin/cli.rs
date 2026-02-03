use clap::Parser;
use email_spoof_detector::domain_verdict::{calculate_domain_verdict, resolve_dkim, resolve_spf_structured};
use email_spoof_detector::{
    dns::{DnsResolver, ResolverTrait},
    email_verdict::analyze_email,
    parse::parse_email,
};
use serde_json::json;

#[derive(Parser)]
struct Cli {
    /// Path to .eml file (optional)
    #[arg(short, long)]
    input: Option<String>,

    /// Domain to analyze (optional)
    #[arg(short, long)]
    domain: Option<String>,

    /// Output JSON
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Require at least --input or --domain
    if cli.input.is_none() && cli.domain.is_none() {
        eprintln!("Error: You must provide either --input <file> or --domain <domain>.");
        std::process::exit(1);
    }

    // Initialize DNS resolver
    let resolver = DnsResolver::new()?;

    // Case 1: Only domain provided
    if cli.input.is_none() && cli.domain.is_some() {
        let domain = cli.domain.clone().unwrap();
        let exists = resolver.domain_exists(&domain).await;
        let spf_eval = resolve_spf_structured(&resolver, &domain, 0).await;
        let dkim = resolve_dkim(&resolver, &domain).await;
        let dmarc = resolver.resolve_dmarc(&domain).await;
        let verdict = calculate_domain_verdict(exists, &spf_eval, dmarc.as_deref());

        if cli.json {
            let output = json!({
                "domain": domain,
                "exists": exists,
                "spf": spf_eval,
                "dmarc": dmarc,
                "dkim": dkim,
                "verdict": verdict,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("Domain analysis for: {}", domain);
            println!("  Exists: {}", exists);
            println!(
                "  SPF: strict_all={}, soft_all={}",
                spf_eval.has_strict_all, spf_eval.has_soft_all
            );
            println!("  DMARC record: {}", dmarc.as_deref().unwrap_or("None"));
            println!("  DKIM record: {}", dkim);
            println!("  Verdict: {:?}", verdict);
        }
        return Ok(());
    }

    // Case 2: Email input provided
    let mut parsed_email = if let Some(input_path) = cli.input.clone() {
        let raw = std::fs::read(&input_path)?;
        Some(parse_email(&raw)?)
    } else {
        None
    };

    // Case 3: Override from domain if --domain provided
    if let Some(domain_override) = cli.domain.clone() {
        if let Some(ref mut parsed) = parsed_email {
            parsed.from = Some(domain_override);
        }
    }

    let parsed = parsed_email.expect("Parsed email must exist");

    // Analyze email using your existing engine
    let result = analyze_email(&parsed, &resolver).await?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Verdict: {:?}", result.verdict);
        println!("Evidence:");
        println!("  From domain: {:?}", result.evidence.from_domain);
        println!("  Domain valid: {}", result.evidence.domain_valid);
        println!("  SPF policy: {:?}", result.evidence.spf_policy);
        println!("  DMARC policy: {:?}", result.evidence.dmarc_policy);
        println!("  DKIM present: {}", result.evidence.dkim_present);
        println!("  Alignment OK: {}", result.evidence.alignment_ok);
    }

    Ok(())
}
