//! Explicitly unattested local development server.

use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use spr_tvc_decryption_service::{local_unattested_service, router};
use spr_tvc_enclave::serve;

#[derive(Debug, Parser)]
#[command(name = "spr-tvc-decryption-service-local")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44030)]
    port: u16,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let address = SocketAddr::new(cli.host, cli.port);
    eprintln!(
        "LOCAL DEVELOPMENT ONLY: unattested decryption service on {address}; do not use funds"
    );
    serve(address, router(local_unattested_service())).await
}
