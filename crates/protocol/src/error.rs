//! Named errors without secret-bearing free-form messages.

use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::{Deserialize, Serialize};

/// Protocol and verification error codes from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ErrorCode {
    UnsupportedVersion,
    RequestTooLarge,
    InvalidEncryptedEnvelope,
    ReleaseBindingMismatch,
    QuorumKeyEpochMismatch,
    InvalidWalletDescriptor,
    WalletBindingMismatch,
    UnauthorizedClient,
    ExpiredRequest,
    TurnkeyEvidenceInvalid,
    InvalidCanonicalJson,
    DuplicateJsonField,
    UnknownJsonField,
    InvalidHex,
    InvalidDecimal,
    InvalidPublicKey,
    InvalidSignature,
    HighSSignature,
    DerSignatureRejected,
    CompressedKeyRejected,
    DoubleHashRejected,
    UnsupportedProofPath,
    BootProofUnverified,
    DiscoveryUntrusted,
    ProductionClaimRejected,
    ReleasePolicyInvalid,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::RequestTooLarge => "RequestTooLarge",
            Self::InvalidEncryptedEnvelope => "InvalidEncryptedEnvelope",
            Self::ReleaseBindingMismatch => "ReleaseBindingMismatch",
            Self::QuorumKeyEpochMismatch => "QuorumKeyEpochMismatch",
            Self::InvalidWalletDescriptor => "InvalidWalletDescriptor",
            Self::WalletBindingMismatch => "WalletBindingMismatch",
            Self::UnauthorizedClient => "UnauthorizedClient",
            Self::ExpiredRequest => "ExpiredRequest",
            Self::TurnkeyEvidenceInvalid => "TurnkeyEvidenceInvalid",
            Self::InvalidCanonicalJson => "InvalidCanonicalJson",
            Self::DuplicateJsonField => "DuplicateJsonField",
            Self::UnknownJsonField => "UnknownJsonField",
            Self::InvalidHex => "InvalidHex",
            Self::InvalidDecimal => "InvalidDecimal",
            Self::InvalidPublicKey => "InvalidPublicKey",
            Self::InvalidSignature => "InvalidSignature",
            Self::HighSSignature => "HighSSignature",
            Self::DerSignatureRejected => "DerSignatureRejected",
            Self::CompressedKeyRejected => "CompressedKeyRejected",
            Self::DoubleHashRejected => "DoubleHashRejected",
            Self::UnsupportedProofPath => "UnsupportedProofPath",
            Self::BootProofUnverified => "BootProofUnverified",
            Self::DiscoveryUntrusted => "DiscoveryUntrusted",
            Self::ProductionClaimRejected => "ProductionClaimRejected",
            Self::ReleasePolicyInvalid => "ReleasePolicyInvalid",
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

/// Typed error. Display is the code name only: no IDs, payloads, or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvcError {
    pub code: ErrorCode,
}

impl TvcError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl Display for TvcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.code, f)
    }
}

impl std::error::Error for TvcError {}

impl From<ErrorCode> for TvcError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

/// Unauthenticated public errors. These MUST NOT reveal wallet or key existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PublicError {
    RequestTooLarge,
    MethodNotAllowed,
    NotFound,
    Unavailable,
    InvalidRequest,
}

impl PublicError {
    pub fn status(self) -> u16 {
        match self {
            Self::RequestTooLarge => 413,
            Self::MethodNotAllowed => 405,
            Self::NotFound => 404,
            Self::Unavailable => 503,
            Self::InvalidRequest => 400,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestTooLarge => "RequestTooLarge",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::NotFound => "NotFound",
            Self::Unavailable => "Unavailable",
            Self::InvalidRequest => "InvalidRequest",
        }
    }
}
