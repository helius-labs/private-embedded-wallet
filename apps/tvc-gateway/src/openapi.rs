//! The public API as gatekeeper serves it, as OpenAPI 3.1. `openapi.json` is
//! this document; `BLESS_OPENAPI=1 cargo test` rewrites it.

use strum::VariantNames;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::openapi::{RefOr, Schema};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::error::{ApiError, Problem};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Helius Private Wallet API",
        version = "1",
        description = "The backend of the Zolana private embedded wallet. Each successful enclave \
                       answer carries the Boot Proof of the replica that gave it; a session also \
                       carries discovery and the ping. The client verifies them against the \
                       release it pins.",
    ),
    servers((url = "https://beta-devnet.helius-rpc.com", description = "Devnet")),
    paths(crate::app::session, crate::app::enroll, crate::app::operations),
    components(schemas(Problem)),
    modifiers(&HeliusApiKey, &ErrorCodes),
    security(("api-key" = [])),
)]
pub struct ApiDoc;

/// The enclave's `QosPingRequest`.
#[derive(ToSchema)]
#[allow(dead_code)]
pub(crate) struct PingRequest {
    version: u8,
    /// A random challenge in a QOS P-256 envelope to the release's quorum key, hex.
    encrypted_challenge: String,
}

struct HeliusApiKey;

impl Modify for HeliusApiKey {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "api-key",
                SecurityScheme::ApiKey(ApiKey::Query(ApiKeyValue::with_description(
                    "api-key",
                    "Your Helius API key.",
                ))),
            );
    }
}

/// Lists every error code in `Problem.code`.
struct ErrorCodes;

impl Modify for ErrorCodes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let code = openapi
            .components
            .as_mut()
            .and_then(|components| components.schemas.get_mut("Problem"))
            .and_then(|problem| match problem {
                RefOr::T(Schema::Object(problem)) => problem.properties.get_mut("code"),
                _ => None,
            });
        if let Some(RefOr::T(Schema::Object(code))) = code {
            code.enum_values = Some(ApiError::VARIANTS.iter().map(|&v| v.into()).collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_openapi_document_is_current() {
        let current = ApiDoc::openapi()
            .to_pretty_json()
            .expect("the document serializes")
            + "\n";
        if std::env::var_os("BLESS_OPENAPI").is_some() {
            std::fs::write("openapi.json", &current).expect("openapi.json is writable");
        }
        let committed = std::fs::read_to_string("openapi.json").unwrap_or_default();
        assert!(
            committed == current,
            "openapi.json is stale; run `BLESS_OPENAPI=1 cargo test` in apps/tvc-gateway"
        );
    }
}
