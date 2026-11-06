use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Every failure the gateway returns, as an RFC 9457 problem:
/// `{"title", "status", "detail", "code"}`, where `code` is the variant name.
///
/// Gatekeeper re-sends any 5xx up to twice. A failure after the request
/// reached the enclave or Turnkey is a 424, never a 5xx.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    thiserror::Error,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::VariantNames,
)]
pub enum ApiError {
    #[error("the body is not the JSON this endpoint takes")]
    InvalidJson,
    #[error("the enrollment names an invalid organization, wallet, address or client key")]
    InvalidEnrollmentRequest,
    #[error("the enrollment is more than five minutes old or more than a minute ahead")]
    StaleEnrollment,
    #[error("the wallet address did not sign this enrollment")]
    InvalidOwnerEnrollmentSignature,

    #[error("the request did not come through gatekeeper")]
    OriginAuthRequired,
    #[error("the request names no valid project")]
    ProjectRequired,
    #[error("the request carries no Helius API key")]
    ApiKeyRequired,
    #[error("Helius does not know this API key")]
    ApiKeyInvalid,
    #[error("the API key's project cannot use WaaS: its plan, or the WaaS rollout")]
    WaasNotEnabled,

    #[error("this gateway did not provision the descriptor for the current release")]
    InvalidDescriptor,
    #[error("the descriptor's client key is revoked")]
    ClientKeyRevoked,
    #[error("the wallet does not hold the claimed address")]
    WalletNotOwned,
    #[error("the wallet's sub-organization belongs to another project")]
    SubOrganizationNotOwned,
    #[error("Turnkey refused the ownership check")]
    TurnkeyRejected,

    #[error("no such endpoint")]
    NotFound,
    #[error("an operation with this ciphertext is still running")]
    OperationInProgress,
    #[error("the body is too large")]
    RequestTooLarge,
    #[error("too many requests in flight")]
    TooManyInFlight,

    #[error("the enclave did not answer")]
    EnclaveUnavailable,
    #[error("the enclave's answer is malformed")]
    InvalidEnclaveAnswer,
    #[error("the enclave's answer is too large")]
    UpstreamResponseTooLarge,
    #[error("Turnkey has no Boot Proof for the replica that answered")]
    BootProofUnavailable,
    #[error("Turnkey did not answer")]
    TurnkeyUnavailable,
    #[error("Turnkey refused this gateway's API key")]
    TurnkeyUnauthorized,
    #[error("Turnkey rate-limited this gateway")]
    TurnkeyRateLimited,
    #[error("the replay guard did not answer")]
    ReplayGuardUnavailable,
    #[error("the descriptor could not be signed")]
    ProvisionerUnavailable,
    #[error("the wallet grant could not be signed")]
    WalletGrantUnavailable,
    #[error("the API key could not be checked")]
    ApiKeyLookupUnavailable,

    #[error("the gateway clock is unavailable")]
    ClockUnavailable,
    #[error("the release this gateway issues descriptors under has expired")]
    ReleaseExpired,
}

/// An RFC 9457 problem; `type` is omitted, so it is `about:blank`.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Problem {
    /// The HTTP status phrase.
    #[schema(value_type = String)]
    title: &'static str,
    status: u16,
    detail: String,
    /// What went wrong, for a program to act on.
    #[schema(value_type = String)]
    code: &'static str,
}

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RETRY_AFTER_SECS: HeaderValue = HeaderValue::from_static("1");

impl ApiError {
    #[inline]
    pub fn code(self) -> &'static str {
        self.into()
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidJson
            | Self::InvalidEnrollmentRequest
            | Self::StaleEnrollment
            | Self::InvalidOwnerEnrollmentSignature => StatusCode::BAD_REQUEST,
            Self::OriginAuthRequired
            | Self::ProjectRequired
            | Self::ApiKeyRequired
            | Self::ApiKeyInvalid => StatusCode::UNAUTHORIZED,
            Self::InvalidDescriptor
            | Self::ClientKeyRevoked
            | Self::WalletNotOwned
            | Self::SubOrganizationNotOwned
            | Self::TurnkeyRejected
            | Self::WaasNotEnabled => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::OperationInProgress => StatusCode::CONFLICT,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyInFlight => StatusCode::TOO_MANY_REQUESTS,
            Self::EnclaveUnavailable
            | Self::InvalidEnclaveAnswer
            | Self::UpstreamResponseTooLarge
            | Self::BootProofUnavailable
            | Self::TurnkeyUnavailable
            | Self::TurnkeyUnauthorized
            | Self::TurnkeyRateLimited
            | Self::ReplayGuardUnavailable
            | Self::ProvisionerUnavailable
            | Self::WalletGrantUnavailable
            | Self::ApiKeyLookupUnavailable => StatusCode::FAILED_DEPENDENCY,
            Self::ClockUnavailable | Self::ReleaseExpired => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// A failure worth retrying soon with the same request.
    const fn retry_after(self) -> Option<HeaderValue> {
        match self {
            Self::TooManyInFlight | Self::OperationInProgress => Some(RETRY_AFTER_SECS),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let problem = Problem {
            title: status.canonical_reason().unwrap_or("Error"),
            status: status.as_u16(),
            detail: self.to_string(),
            code: self.code(),
        };
        let mut response = (status, Json(problem)).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, PROBLEM_JSON);
        if let Some(retry_after) = self.retry_after() {
            headers.insert(header::RETRY_AFTER, retry_after);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_is_the_variant_name_and_no_failure_is_retried_by_gatekeeper() {
        assert_eq!(ApiError::StaleEnrollment.code(), "StaleEnrollment");
        assert_eq!("StaleEnrollment".parse(), Ok(ApiError::StaleEnrollment));
        for error in [ApiError::EnclaveUnavailable, ApiError::TurnkeyUnavailable] {
            assert_eq!(error.status(), StatusCode::FAILED_DEPENDENCY);
        }
    }

    #[tokio::test]
    async fn a_failure_is_a_problem_document() {
        let response = ApiError::TooManyInFlight.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&PROBLEM_JSON)
        );
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&RETRY_AFTER_SECS)
        );
        let body = axum::body::to_bytes(response.into_body(), 4_096)
            .await
            .expect("body reads");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("body is JSON"),
            serde_json::json!({
                "title": "Too Many Requests",
                "status": 429,
                "detail": "too many requests in flight",
                "code": "TooManyInFlight",
            })
        );
    }
}
