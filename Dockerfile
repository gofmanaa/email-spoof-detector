# Stage 1: Build stage
FROM rust:1.93.0-slim-trixie AS builder
  
  # Set environment variables for reproducible builds
ENV CARGO_HOME=/usr/local/cargo \
RUSTUP_HOME=/usr/local/rustup \
CARGO_TERM_COLOR=always

WORKDIR /app
  
  # Copy Cargo files first for caching dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src
  
  # Build release version
RUN cargo build --release
  
  # Stage 2: Minimal runtime stage
FROM debian:bullseye-slim
  
  # Install only what is needed to run the app
RUN apt-get update && \
apt-get install -y ca-certificates && \
rm -rf /var/lib/apt/lists/*

WORKDIR /app
  
  # Copy the compiled binary from builder stage
COPY --from=builder /app/target/release/web ./web
  
  # Use a non-root user
RUN useradd -m appuser
USER appuser
  
  # Expose default web port
EXPOSE 8080
  
  # Run the web app
CMD ["./web"]
