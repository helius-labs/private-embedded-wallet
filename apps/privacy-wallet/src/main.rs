use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use spr_tvc_enclave::{serve, Release};
use zolana_tvc_privacy_wallet::{load_qos_state, router};

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-privacy-wallet")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44020)]
    port: u16,

    #[command(flatten)]
    release: Release,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let state = load_qos_state(cli.release)?;
    serve(SocketAddr::new(cli.host, cli.port), router(state)).await
}
