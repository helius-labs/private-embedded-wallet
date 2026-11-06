//! Signs the fixed bootstrap derivation message via Turnkey or the local testkit.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use qos_p256::P256Pair;
use turnkey_api_key_stamper::Stamp;
use turnkey_client::generated::external::activity::v1::SignRawPayloadRequest;
use turnkey_client::generated::immutable::{
    activity::v1::{
        intent, result, ActivityStatus, ActivityType, SignRawPayloadIntentV2, SignRawPayloadResult,
    },
    common::v1::{HashFunction, PayloadEncoding},
};
use turnkey_client::generated::services::coordinator::public::v1::{
    ActivityResponse, GetActivityRequest,
};
use turnkey_client::{ActivityResult, TurnkeyClient, TurnkeyClientError};

use crate::turnkey::QosTurnkeyStamper;

/// The Turnkey key a descriptor names. `sign_with` is the wallet's Solana
/// address, which Turnkey accepts as the key selector.
pub(crate) struct WalletKey<'a> {
    pub organization_id: &'a str,
    pub sign_with: &'a str,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyError {
    /// The custodian could not be reached or answered unusably.
    Unavailable,
    /// The custodian declined to sign.
    Declined,
}

pub(crate) struct RawSignature {
    pub signature: [u8; 64],
    /// The Turnkey activity that signed.
    pub activity_id: String,
}

#[async_trait]
pub(crate) trait Custody: Send + Sync {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError>;
}

pub(crate) struct TurnkeyCustody {
    quorum: Arc<P256Pair>,
}

impl TurnkeyCustody {
    pub(crate) fn new(quorum: Arc<P256Pair>) -> Self {
        Self { quorum }
    }

    fn client(&self) -> Result<TurnkeyClient<QosTurnkeyStamper>, CustodyError> {
        TurnkeyClient::builder()
            .api_key(QosTurnkeyStamper::new(Arc::clone(&self.quorum)))
            .build()
            .map_err(|_| CustodyError::Unavailable)
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CustodyError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|_| CustodyError::Unavailable)
}

#[async_trait]
impl Custody for TurnkeyCustody {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError> {
        let activity = sign_with_approval(
            &self.client()?,
            wallet.organization_id,
            timestamp_ms,
            SignRawPayloadIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                payload: hex::encode(payload),
                encoding: PayloadEncoding::Hexadecimal,
                hash_function: HashFunction::NotApplicable,
            },
        )
        .await?;
        let (r, s) = (
            decode_hex(&activity.result.r)?,
            decode_hex(&activity.result.s)?,
        );
        if r.len() != 32 || s.len() != 32 {
            return Err(CustodyError::Unavailable);
        }
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        Ok(RawSignature {
            signature,
            activity_id: activity.activity_id,
        })
    }
}

/// Poll the original activity: resubmitting would create another approval request.
/// The operation handler enforces the deadline.
async fn sign_with_approval<S: Stamp>(
    client: &TurnkeyClient<S>,
    organization_id: &str,
    timestamp_ms: u64,
    params: SignRawPayloadIntentV2,
) -> Result<ActivityResult<SignRawPayloadResult>, CustodyError> {
    let mut request = SignRawPayloadRequest {
        r#type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2".to_owned(),
        timestamp_ms: timestamp_ms.to_string(),
        organization_id: organization_id.to_owned(),
        parameters: Some(params.clone()),
        generate_app_proofs: None,
    };
    let mut permission_retries = 0;
    let mut activity = loop {
        // The SDK's sign_raw_payload resubmits Pending activities. Submit directly
        // so that once an activity exists, all subsequent requests query its id.
        match client
            .process_request::<_, ActivityResponse>(
                &request,
                "/public/v1/submit/sign_raw_payload".to_owned(),
            )
            .await
        {
            Ok(response) => break response.activity.ok_or(CustodyError::Unavailable)?,
            // New grants take time to propagate. Denials are cached, so retry
            // them with a fresh timestamp. Other errors may have created an activity.
            Err(TurnkeyClientError::UnexpectedHttpStatus(403, _)) if permission_retries < 10 => {
                permission_retries += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
                request.timestamp_ms = client.current_timestamp().to_string();
            }
            Err(_) => return Err(CustodyError::Unavailable),
        }
    };
    let activity_id = activity.id.clone();
    let expected_intent = intent::Inner::SignRawPayloadIntentV2(params);
    loop {
        if activity.id != activity_id
            || activity.organization_id != organization_id
            || activity.r#type != ActivityType::SignRawPayloadV2
            || activity
                .intent
                .as_ref()
                .and_then(|intent| intent.inner.as_ref())
                != Some(&expected_intent)
        {
            return Err(CustodyError::Unavailable);
        }
        match activity.status {
            ActivityStatus::Completed => {
                let Some(result::Inner::SignRawPayloadResult(result)) =
                    activity.result.and_then(|result| result.inner)
                else {
                    return Err(CustodyError::Unavailable);
                };
                return Ok(ActivityResult {
                    result,
                    activity_id,
                    status: activity.status,
                    app_proofs: activity.app_proofs,
                });
            }
            ActivityStatus::ConsensusNeeded | ActivityStatus::Pending => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ActivityStatus::Rejected | ActivityStatus::Failed => {
                return Err(CustodyError::Declined)
            }
            _ => return Err(CustodyError::Unavailable),
        }
        activity = client
            .get_activity(GetActivityRequest {
                organization_id: organization_id.to_owned(),
                activity_id: activity_id.clone(),
            })
            .await
            .map_err(|_| CustodyError::Unavailable)?
            .activity
            .ok_or(CustodyError::Unavailable)?;
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        Router,
    };
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use turnkey_client::TurnkeyP256ApiKey;

    fn params() -> SignRawPayloadIntentV2 {
        SignRawPayloadIntentV2 {
            sign_with: "wallet".into(),
            payload: "abcd".into(),
            encoding: PayloadEncoding::Hexadecimal,
            hash_function: HashFunction::NotApplicable,
        }
    }

    fn activity(status: &str) -> (StatusCode, Value) {
        (
            StatusCode::OK,
            json!({"activity": {
                "id": "request-1", "organizationId": "org", "status": status,
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fingerprint",
                "intent": {"signRawPayloadIntentV2": params()},
                "result": {"signRawPayloadResult": {"r": "11", "s": "22", "v": ""}},
                "appProofs": [{"scheme": "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256", "publicKey": "public",
                    "proofPayload": "proof", "signature": "signature"}]
            }}),
        )
    }

    type Requests = Arc<Mutex<Vec<(String, Value)>>>;

    async fn server(
        responses: Vec<(StatusCode, Value)>,
    ) -> (
        TurnkeyClient<TurnkeyP256ApiKey>,
        tokio::task::JoinHandle<()>,
        Requests,
    ) {
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let requests: Requests = Arc::default();
        let captured = Arc::clone(&requests);
        let app = Router::new().fallback(move |request: Request<Body>| {
            let responses = Arc::clone(&responses);
            let captured = Arc::clone(&captured);
            async move {
                let path = request.uri().path().to_owned();
                let body = to_bytes(request.into_body(), 16_384).await.unwrap();
                captured
                    .lock()
                    .unwrap()
                    .push((path, serde_json::from_slice(&body).unwrap()));
                let mut responses = responses.lock().unwrap();
                let response = if responses.len() > 1 {
                    responses.pop_front().unwrap()
                } else {
                    responses[0].clone()
                };
                (
                    response.0,
                    [("content-type", "application/json")],
                    response.1.to_string(),
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
        let client = TurnkeyClient::builder()
            .api_key(TurnkeyP256ApiKey::generate())
            .base_url(url)
            .build()
            .unwrap();
        (client, task, requests)
    }

    #[tokio::test]
    async fn approval_polls_the_original_activity() {
        for initial_status in [
            "ACTIVITY_STATUS_CONSENSUS_NEEDED",
            "ACTIVITY_STATUS_PENDING",
        ] {
            let (client, task, requests) = server(vec![
                activity(initial_status),
                activity("ACTIVITY_STATUS_PENDING"),
                activity("ACTIVITY_STATUS_COMPLETED"),
            ])
            .await;
            let result = sign_with_approval(&client, "org", 1000, params())
                .await
                .unwrap();
            task.abort();
            assert_eq!(result.activity_id, "request-1");
            assert_eq!(result.result.r, "11");
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0].0, "/public/v1/submit/sign_raw_payload");
            for (path, body) in &requests[1..] {
                assert_eq!(path, "/public/v1/query/get_activity");
                assert_eq!(
                    body,
                    &json!({"organizationId": "org", "activityId": "request-1"})
                );
            }
        }
    }

    #[tokio::test]
    async fn rejected_or_substituted_activities_cannot_complete_bootstrap() {
        for (field, value, declined) in [
            ("status", "ACTIVITY_STATUS_REJECTED", true),
            ("status", "ACTIVITY_STATUS_FAILED", true),
            ("id", "different-activity", false),
            ("organizationId", "different-org", false),
            ("type", "ACTIVITY_TYPE_SIGN_TRANSACTION_V2", false),
            ("payload", "different-message", false),
        ] {
            let (status, mut response) = activity("ACTIVITY_STATUS_COMPLETED");
            if field == "payload" {
                response["activity"]["intent"]["signRawPayloadIntentV2"][field] = json!(value);
            } else {
                response["activity"][field] = json!(value);
            }
            let (client, task, _) = server(vec![
                activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
                (status, response),
            ])
            .await;
            let error = sign_with_approval(&client, "org", 1000, params())
                .await
                .unwrap_err();
            task.abort();
            assert_eq!(
                error,
                if declined {
                    CustodyError::Declined
                } else {
                    CustodyError::Unavailable
                }
            );
        }
    }

    #[tokio::test]
    async fn a_new_grant_can_propagate_before_the_first_activity_is_created() {
        let (client, task, requests) = server(vec![
            (
                StatusCode::FORBIDDEN,
                json!({"code": 7, "message": "permission denied"}),
            ),
            activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            activity("ACTIVITY_STATUS_COMPLETED"),
        ])
        .await;
        let result = sign_with_approval(&client, "org", 1000, params())
            .await
            .unwrap();
        task.abort();
        assert_eq!(result.activity_id, "request-1");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, requests[1].0);
        assert_ne!(requests[0].1["timestampMs"], requests[1].1["timestampMs"]);
        let mut retried = requests[0].1.clone();
        retried["timestampMs"] = requests[1].1["timestampMs"].clone();
        assert_eq!(retried, requests[1].1);
        assert_eq!(requests[2].0, "/public/v1/query/get_activity");
    }

    #[tokio::test]
    async fn other_submission_errors_are_not_retried() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
            StatusCode::OK,
        ] {
            let (client, task, requests) = server(vec![
                (status, json!({"message": "failure"})),
                activity("ACTIVITY_STATUS_COMPLETED"),
            ])
            .await;
            assert_eq!(
                sign_with_approval(&client, "org", 1000, params())
                    .await
                    .unwrap_err(),
                CustodyError::Unavailable
            );
            task.abort();
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn permission_retries_are_bounded() {
        let (client, task, requests) = server(vec![(
            StatusCode::FORBIDDEN,
            json!({"code": 7, "message": "permission denied"}),
        )])
        .await;
        assert_eq!(
            sign_with_approval(&client, "org", 1000, params())
                .await
                .unwrap_err(),
            CustodyError::Unavailable
        );
        task.abort();
        assert_eq!(requests.lock().unwrap().len(), 11);
    }

    #[tokio::test]
    async fn waiting_for_approval_can_be_cancelled_at_the_operation_deadline() {
        for initial_response in [
            activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            (StatusCode::FORBIDDEN, json!({"code": 7})),
        ] {
            let (client, task, requests) = server(vec![initial_response]).await;
            let result = tokio::time::timeout(
                Duration::from_millis(100),
                sign_with_approval(&client, "org", 1000, params()),
            )
            .await;
            task.abort();
            assert!(result.is_err());
            assert_eq!(
                requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(path, _)| path.ends_with("sign_raw_payload"))
                    .count(),
                1
            );
        }
    }
}
