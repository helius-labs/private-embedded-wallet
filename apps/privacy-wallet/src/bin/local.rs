//! Explicitly unattested local development server.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::Parser;
use qos_p256::P256Pair;
use zeroize::Zeroizing;
use zolana_tvc_privacy_wallet::{
    local_testkit_qos_seeds, local_unattested_state, router, LocalProver, LocalProverTrust,
};

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-privacy-wallet-local")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44020)]
    port: u16,

    /// Disposable Solana keypair JSON used by both the Node test and local custody.
    #[arg(long)]
    wallet_keypair: PathBuf,

    /// The plaintext prover the stand-in attested prover forwards to.
    #[arg(long, default_value = "http://127.0.0.1:3001")]
    prover_url: String,

    /// Where the stand-in attested prover listens; clients prove through it.
    #[arg(long, default_value_t = 44021)]
    prover_tee_port: u16,

    /// Seal witnesses to the devnet TEE prover, verified against the production
    /// Nitro root under the devnet prover policy key, and start no stand-in
    /// prover. `--prover-url` and `--prover-tee-port` are unused.
    #[arg(long)]
    live_prover: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let encoded = std::fs::read(&cli.wallet_keypair)?;
    let keypair: Vec<u8> = serde_json::from_slice(&encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid keypair JSON"))?;
    if keypair.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the wallet keypair must contain exactly 64 bytes",
        ));
    }
    let mut wallet_secret = Zeroizing::new([0_u8; 32]);
    wallet_secret.copy_from_slice(&keypair[..32]);

    // Stable test-only QOS keys let the SDK pin the local server instead of
    // trusting whatever process happens to answer on the loopback port.
    let (ephemeral_seed, quorum_seed) = local_testkit_qos_seeds();
    let ephemeral = P256Pair::from_master_seed(&Zeroizing::new(ephemeral_seed))
        .map_err(|_| io::Error::other("failed to derive local ephemeral key"))?;
    let quorum = P256Pair::from_master_seed(&Zeroizing::new(quorum_seed))
        .map_err(|_| io::Error::other("failed to derive local quorum key"))?;
    let address = SocketAddr::new(cli.host, cli.port);
    let state = if cli.live_prover {
        let state =
            local_unattested_state(ephemeral, quorum, *wallet_secret, LocalProverTrust::Image);
        eprintln!(
            "LOCAL DEVELOPMENT ONLY: unattested mock custody listening on {address}, sealing \
             to provers the {} prover policy admits; do not use funds",
            spr_tvc_enclave::NETWORK
        );
        state
    } else {
        let prover = LocalProver::new(&cli.prover_url);
        let state = local_unattested_state(
            ephemeral,
            quorum,
            *wallet_secret,
            LocalProverTrust::StandIn(prover.anchors()),
        );
        let prover_address = SocketAddr::new(cli.host, cli.prover_tee_port);
        let prover_listener = tokio::net::TcpListener::bind(prover_address).await?;
        eprintln!(
            "LOCAL DEVELOPMENT ONLY: unattested mock custody listening on {address} and a \
             fixture-attested prover on {prover_address}; do not use funds"
        );
        tokio::spawn(async move {
            if let Err(error) = axum::serve(prover_listener, prover.router()).await {
                eprintln!("local attested prover stopped: {error}");
            }
        });
        state
    };
    spr_tvc_enclave::serve(address, router(state)).await
}
