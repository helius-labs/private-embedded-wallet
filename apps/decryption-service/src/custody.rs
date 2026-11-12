//! What a release pins about the master seed: which seed, and who holds its backup.

use std::io;

use zolana_tvc_protocol::crypto::parse_uncompressed_sec1;
use zolana_tvc_protocol::encoding::{decode_lower_hex, decode_lower_hex_array};

// The custody arguments a QOS manifest starts a release with. Not a doc comment: clap would print it.
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct Custody {
    /// The seed this release serves; without it the release only draws and backs up a seed.
    #[arg(long, value_parser = commitment)]
    pub seed_commitment: Option<[u8; 32]>,

    /// A backup holder's 65-byte uncompressed P-256 encryption key, in hex; repeat per holder.
    #[arg(long = "backup-holder", value_parser = holder)]
    pub backup_holders: Vec<Vec<u8>>,

    /// How many backup shares rebuild the seed.
    #[arg(long)]
    pub backup_threshold: Option<u8>,
}

impl Custody {
    /// Holders and threshold come together, with at least two holders needed and at most 255.
    pub fn check(&self) -> io::Result<()> {
        let holders = self.backup_holders.len();
        let valid = match self.backup_threshold {
            None => holders == 0,
            Some(threshold) => {
                threshold >= 2 && usize::from(threshold) <= holders && holders <= 255
            }
        };
        if valid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup holders need a threshold from 2 to their count",
            ))
        }
    }
}

fn commitment(value: &str) -> Result<[u8; 32], String> {
    decode_lower_hex_array(value).map_err(|_| "must be 32 bytes of lowercase hex".to_owned())
}

fn holder(value: &str) -> Result<Vec<u8>, String> {
    let key = decode_lower_hex(value).map_err(|_| "must be lowercase hex".to_owned())?;
    parse_uncompressed_sec1(&key).map_err(|_| "must be an uncompressed P-256 key".to_owned())?;
    Ok(key)
}
