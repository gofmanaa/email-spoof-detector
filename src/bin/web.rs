use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use env_logger::Env;
use email_spoof_detector::{dns::DnsResolver, email_verdict::analyze_email, parse::parse_email};
use serde::Deserialize;

#[derive(Deserialize)]
struct AnalyzeRequest {
    raw_email: String, // base64 or plain text email
}

async fn analyze(req: web::Json<AnalyzeRequest>) -> impl Responder {
    let raw_bytes = req.raw_email.as_bytes();

    let parsed = match parse_email(raw_bytes) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().body(format!("Failed to parse email: {}", e)),
    };

    let resolver = match DnsResolver::new() {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("DNS resolver error: {}", e));
        }
    };

    match analyze_email(&parsed, &resolver).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().body(format!("Analysis error: {}", e)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    log::info!("Starting Email Spoof Analysis Service");

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    log::info!("Binding to {}:{}", host, port);

    HttpServer::new(|| {
        App::new()
            .route("/analyze", web::post().to(analyze))
            .wrap(actix_web::middleware::Logger::default())
    })
        .workers(num_cpus::get())         // spawn one worker per CPU core
        .keep_alive(std::time::Duration::from_secs(75)) // typical production keep-alive
        .max_connections(1_000)          // limit simultaneous connections
        .bind((host.as_str(), port))?     // bind to dynamic host/port
        .run()
        .await
}
