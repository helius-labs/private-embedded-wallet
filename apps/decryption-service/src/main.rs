use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use spr_tvc_decryption_service::{load_qos_state, router, Custody};
use spr_tvc_enclave::{serve, Release};

#[derive(Debug, Parser)]
#[command(name = "spr-tvc-decryption-service")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44030)]
    port: u16,

    #[command(flatten)]
    release: Release,

    #[command(flatten)]
    custody: Custody,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let state = load_qos_state(cli.release, cli.custody)?;
    serve(SocketAddr::new(cli.host, cli.port), router(state)).await
}
