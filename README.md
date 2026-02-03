# Email Spoof Detector

## Overview

In today’s world, it is increasingly easy for attackers to **spoof domains** and make emails appear as if they are coming from legitimate sources. If you have ever received a suspicious email that seemed to be from an official domain, you may have been targeted by scammers.

This tool helps you **analyze and validate emails** by examining headers and checking whether the sending domain is legitimate and properly configured. It uses structured SPF, DKIM, and DMARC checks to determine the authenticity and email posture of a domain.

## Features

- Parse email headers and extract sending domain
- Validate SPF records recursively
- Check DKIM selectors for proper configuration
- Evaluate DMARC policies (reject/quarantine)
- Assess domain age and MX records for legitimacy
- Compute a **verdict**: Strong, Medium, Weak, or Invalid
- Provides CLI and web API interfaces


## Installation

Clone the repository and build the project:

```bash
git clone https://github.com/yourusername/email-spoof-detector.git
cd email-spoof-detector
cargo build --release
```

## The binaries are located in:
```
target/release/cli
target/release/web
```

# Usage

## CLI

```text
./cli --input <email_file.eml>
./cli --domain google.com
```

## Web API

Start the server:
```text
./web
```

Send a POST request to /analyze with the raw email content.

## Verdict Explanation

`Strong`: Domain has strict SPF, valid DKIM, and DMARC reject policy; domain is established.

`Medium`: Domain has some authentication configured but is missing one signal.

`Weak`: Domain has minimal or misconfigured authentication.

`Invalid`: Domain does not exist or cannot be validated.

## Security Considerations

No secrets are stored or transmitted

DNS and WHOIS queries are handled safely and asynchronously

No unsafe Rust code; memory safety enforced by compiler


# License

This project is licensed under MIT License.

