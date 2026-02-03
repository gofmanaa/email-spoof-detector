use anyhow::Result;
use clap::Parser;
use lettre::{
    message::{Mailbox, Message},
    transport::smtp::SmtpTransport,
    Transport,
};
use std::fs;

// spoof-tester \
//   --from ceo@my-test.com \
//   --to victim@localhost \
//   --subject "Test" \
//   --body "This is a spoof test" \
//   --smtp localhost:1025 \
//   --eml-out spoof.eml
// 
// docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
// cargo run -- \
//   --from ceo@my-test.com \
//   --to victim@localhost \
//   --subject "Payroll update" \
//   --body "Test only" \
//   --smtp localhost:1025

#[derive(Parser)]
#[command(author, version, about = "Email spoofing test tool (lab use only)")]
struct Cli {
    /// Spoofed From address (e.g. ceo@my-test.com)
    #[arg(long)]
    from: String,

    /// Recipient (local test inbox)
    #[arg(long)]
    to: String,

    /// Subject
    #[arg(long, default_value = "Spoofing test")]
    subject: String,

    /// Message body
    #[arg(long, default_value = "This is a controlled spoofing test.")]
    body: String,

    /// SMTP server (ONLY local test servers recommended)
    #[arg(long, default_value = "localhost:1025")]
    smtp: String,

    /// Write .eml file instead of sending
    #[arg(long)]
    eml_out: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let email = Message::builder()
        .from(cli.from.parse::<Mailbox>()?)
        .to(cli.to.parse::<Mailbox>()?)
        .subject(cli.subject)
        .body(cli.body)?;

    // Save to .eml if requested
    if let Some(path) = cli.eml_out {
        let raw = String::from_utf8(email.formatted())?;
        fs::write(&path, raw)?;
        println!("EML written to {}", path);
        return Ok(());
    }

    // Send ONLY to test SMTP
    let mailer = SmtpTransport::builder_dangerous(&cli.smtp)
        .build();

    mailer.send(&email)?;

    println!("Spoof test email sent to {}", cli.smtp);
    Ok(())
}
