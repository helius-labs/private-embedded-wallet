//! Decrypt a canonical `qos_p256` 0.12.1 envelope with the TVC transcription,
//! and encrypt a TVC envelope that the pinned crate can decrypt.

use qos_p256::encrypt::P256EncryptPair;
use qos_p256::P256Pair;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use spr_tvc_protocol::crypto::{qos_decrypt, qos_encrypt};
use spr_tvc_protocol::encoding::decode_lower_hex;

fn fixture_encryption_secret() -> [u8; 32] {
    Sha256::digest(b"spr-tvc-test-encryption-sk").into()
}

#[test]
fn qos_crate_decrypts_committed_tvc_envelope() {
    let body = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/qos-borsh-envelope.json"
    ))
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let envelope = decode_lower_hex(value["envelope"].as_str().unwrap()).unwrap();
    let plaintext = decode_lower_hex(value["plaintext"].as_str().unwrap()).unwrap();
    let secret = fixture_encryption_secret();
    let pair = P256EncryptPair::from_bytes(&Zeroizing::new(secret.to_vec())).unwrap();
    let decrypted = pair
        .decrypt(&envelope)
        .expect("qos_p256 decrypts TVC envelope");
    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn qos_crate_encrypt_decrypts_with_tvc() {
    let pair = P256Pair::generate().unwrap();
    let plaintext = b"qos-crate-interop";
    let envelope = pair.public_key().encrypt(plaintext).unwrap();
    let secret: [u8; 32] = pair.encryption_key().to_bytes().into();
    let decrypted = qos_decrypt(&secret, &envelope).expect("TVC decrypts qos_p256 envelope");
    assert_eq!(decrypted.as_slice(), plaintext);

    let encryption_public = &pair.public_key().to_bytes()[..65];
    let tvc_envelope = qos_encrypt(encryption_public, plaintext).unwrap();
    let qos_plain = pair
        .decrypt(&tvc_envelope)
        .expect("qos_p256 decrypts TVC envelope");
    assert_eq!(&qos_plain[..], plaintext);
}
