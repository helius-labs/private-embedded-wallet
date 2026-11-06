//! Bounded unauthenticated HTTP skeleton for `/health` and `/v1/info`.

use zolana_tvc_protocol::constants::{API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES};
use zolana_tvc_protocol::encoding::jcs_serialize;
use zolana_tvc_protocol::types::{HealthResponse, HealthStatus, ServiceInfo};

/// Unauthenticated public errors. These MUST NOT reveal wallet or key existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicHttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

pub fn public_http_error(error: PublicError) -> PublicHttpResponse {
    let body = format!("{{\"error\":\"{}\"}}", error.as_str());
    PublicHttpResponse {
        status: error.status(),
        content_type: "application/json",
        body: body.into_bytes(),
    }
}

fn json_ok(body: String) -> PublicHttpResponse {
    PublicHttpResponse {
        status: 200,
        content_type: "application/json",
        body: body.into_bytes(),
    }
}

/// Process-readiness and untrusted discovery only.
///
/// `/health` MUST NOT include release, key, or deployment identifiers.
/// `/v1/info` is discovery data, not a trust root.
pub fn handle_public_http(
    method: &str,
    path: &str,
    body: &[u8],
    ready: bool,
    info: &ServiceInfo,
) -> PublicHttpResponse {
    let limit = info
        .max_encrypted_request_bytes
        .min(MAX_ENCRYPTED_REQUEST_BYTES);
    if body.len() as u64 > limit {
        return public_http_error(PublicError::RequestTooLarge);
    }

    match (method, path) {
        ("GET", "/health") => {
            if !ready {
                return public_http_error(PublicError::Unavailable);
            }
            match jcs_serialize(&HealthResponse {
                status: HealthStatus::Healthy,
            }) {
                Ok(body) => json_ok(body),
                Err(_) => public_http_error(PublicError::Unavailable),
            }
        }
        ("GET", "/v1/info") => {
            if info.version != API_VERSION {
                return public_http_error(PublicError::InvalidRequest);
            }
            match jcs_serialize(info) {
                Ok(body) => json_ok(body),
                Err(_) => public_http_error(PublicError::InvalidRequest),
            }
        }
        ("POST", "/health" | "/v1/info") | ("PUT", "/health" | "/v1/info") => {
            public_http_error(PublicError::MethodNotAllowed)
        }
        (_, "/health" | "/v1/info") => public_http_error(PublicError::MethodNotAllowed),
        _ => public_http_error(PublicError::NotFound),
    }
}
