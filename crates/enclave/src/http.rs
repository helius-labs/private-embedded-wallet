//! Plain JSON answers and the generic errors every route answers with.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;

/// Unauthenticated public errors. These MUST NOT reveal wallet or key existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
pub enum PublicError {
    RequestTooLarge,
    MethodNotAllowed,
    NotFound,
    Unavailable,
    InvalidRequest,
    /// An authorized request's wallet descriptor has expired; the client
    /// enrolls its key again.
    DescriptorExpired,
}

impl PublicError {
    fn status(self) -> StatusCode {
        match self {
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::DescriptorExpired => StatusCode::FORBIDDEN,
        }
    }
}

impl IntoResponse for PublicError {
    fn into_response(self) -> Response<Body> {
        let name: &'static str = self.into();
        json(self.status(), format!("{{\"error\":\"{name}\"}}"))
    }
}

/// `200 OK` with `body`, already serialized JSON.
pub fn ok(body: String) -> Response<Body> {
    json(StatusCode::OK, body)
}

fn json(status: StatusCode, body: String) -> Response<Body> {
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.into_bytes(),
    )
        .into_response()
}
