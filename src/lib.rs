pub mod dns;
pub mod domain_verdict;
pub mod email_verdict;
pub mod parse;

pub use dns::DnsResolver;
pub use email_verdict::{AnalysisResult, Evidence, Verdict, analyze_email};
pub use parse::{EmailParsed, extract_domain};
