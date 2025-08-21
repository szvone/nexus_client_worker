//! Nexus Orchestrator Client
//!
//! A client for the Nexus Orchestrator, allowing for proof task retrieval and submission.

use crate::environment::Environment;
use crate::nexus_orchestrator::{
    GetProofTaskRequest, GetProofTaskResponse, NodeType, RegisterNodeRequest, RegisterNodeResponse,
    RegisterUserRequest, SubmitProofRequest, TaskDifficulty, UserResponse,
};
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::system::{estimate_peak_gflops, get_memory_info};
use crate::task::Task;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use prost::Message;
use reqwest::{Client, ClientBuilder, Response};
use reqwest::{Proxy, StatusCode};
use std::sync::OnceLock;
use tokio::time::{Duration, timeout};

// Build timestamp in milliseconds since epoch
static BUILD_TIMESTAMP: &str = "1755639721739";

// User-Agent string with CLI version
const USER_AGENT: &str = concat!("nexus-cli/", "0.10.9");
pub(crate) type ProofPayload = (Vec<u8>, Vec<Vec<u8>>, Vec<String>);

// Privacy-preserving country detection for network optimization.
// Only stores 2-letter country codes (e.g., "US", "CA", "GB") to help route
// requests to the nearest Nexus network servers for better performance.
// No precise location, IP addresses, or personal data is collected or stored.
static COUNTRY_CODE: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    client: Client,
    environment: Environment,
}

impl OrchestratorClient {
    pub fn new(environment: Environment) -> Self {
        // Self {
        //     client: ClientBuilder::new()
        //         .connect_timeout(Duration::from_secs(10))
        //         .timeout(Duration::from_secs(10))
        //         .build()
        //         .expect("Failed to create HTTP client"),
        //     environment,
        // }
        // 固定代理地址（根据需要修改实际代理配置）
        // const PROXY_ADDR: &str = "http://127.0.0.1:2025";

        // 创建带代理的客户端
        let client = ClientBuilder::new()
            // .proxy(Proxy::all(PROXY_ADDR).expect("无效的代理配置")) // 固定代理设置
            .connect_timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true) // 忽略所有证书错误
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            environment,
        }
    }

    fn build_url(&self, endpoint: &str) -> String {
        format!(
            "{}/{}",
            self.environment.orchestrator_url().trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        )
    }

    fn encode_request<T: Message>(request: &T) -> Vec<u8> {
        request.encode_to_vec()
    }

    fn decode_response<T: Message + Default>(bytes: &[u8]) -> Result<T, OrchestratorError> {
        T::decode(bytes).map_err(OrchestratorError::Decode)
    }

    
/// Selects which proof data to attach based on the `task_type`.
///
/// Returns a tuple `(legacy_proof, proofs, individual_proof_hashes)` with the appropriate
/// fields populated:
/// - For `ProofHash`: no proof bytes and no hashes (server derives hash elsewhere).
/// - For `AllProofHashes`: no proof bytes; `individual_proof_hashes` populated.
/// - For other types (e.g. `ProofRequired`): `legacy_proof` is set only when exactly
///   one proof is present (back-compat), and `proofs` contains the vector of full proofs.
pub(crate) fn select_proof_payload(
    task_type: crate::nexus_orchestrator::TaskType,
    legacy_proof: Vec<u8>,
    proofs: Vec<Vec<u8>>,
    individual_proof_hashes: &[String],
) -> ProofPayload {
    match task_type {
        crate::nexus_orchestrator::TaskType::ProofHash => {
            // For ProofHash tasks, don't send proof or individual hashes
            (Vec::new(), Vec::new(), Vec::new())
        }
        crate::nexus_orchestrator::TaskType::AllProofHashes => {
            // For AllProofHashes tasks, don't send proof but send all individual hashes
            (Vec::new(), Vec::new(), individual_proof_hashes.to_vec())
        }
        _ => {
            // For ProofRequired and backward compatibility:
            // - Always include `proofs` as provided
            // - Include `legacy_proof` only when there is exactly one proof, for servers/paths
            //   that still expect a single legacy proof field
            let legacy = if proofs.len() == 1 {
                legacy_proof
            } else {
                Vec::new()
            };
            (legacy, proofs, Vec::new())
        }
    }
}
    async fn handle_response_status(response: Response) -> Result<Response, OrchestratorError> {
        if !response.status().is_success() {
            return Err(OrchestratorError::from_response(response).await);
        }
        Ok(response)
    }

    async fn get_request<T: Message + Default>(
        &self,
        endpoint: &str,
    ) -> Result<T, OrchestratorError> {
        let url = self.build_url(endpoint);
        let response = self
            .client
            .get(&url)
            .header("User-Agent", USER_AGENT)
            .header("X-Build-Timestamp", "1755045583717")
            .send()
            .await?;

        let response = Self::handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    async fn post_request<T: Message + Default>(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<T, OrchestratorError> {
        let url = self.build_url(endpoint);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", USER_AGENT)
            .header("X-Build-Timestamp", BUILD_TIMESTAMP)
            .body(body)
            .send()
            .await?;

        let response = Self::handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }
    async fn post_request_no_response(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<(), OrchestratorError> {
        const MAX_RETRIES: usize = 2;
        const TIMEOUT_SECONDS: u64 = 30;
        let url = self.build_url(endpoint);

        for attempt in 0..MAX_RETRIES {
            match timeout(
                Duration::from_secs(TIMEOUT_SECONDS),
                self.send_request(&url, body.clone()),
            )
            .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => {
                    if let OrchestratorError::Http { status, .. } = &e {
                        if (500..600).contains(status) {
                            continue;
                        }
                    }
                    return Err(e);
                }
                Err(_) => {
                    if attempt == MAX_RETRIES - 1 {
                        return Err(OrchestratorError::MaxRetriesExceeded {
                            retries: MAX_RETRIES,
                        });
                    }
                    continue;
                }
            }
        }

        Err(OrchestratorError::Timeout {
            seconds: TIMEOUT_SECONDS,
        })
    }

    async fn send_request(&self, url: &str, body: Vec<u8>) -> Result<(), OrchestratorError> {
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", USER_AGENT)
            .header("X-Build-Timestamp", BUILD_TIMESTAMP)
            .timeout(Duration::from_secs(15))
            .body(body)
            .send()
            .await
            .map_err(|e| OrchestratorError::Reqwest(e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(OrchestratorError::Http { status, message })
        }
    }
    fn create_signature(
        &self,
        signing_key: &SigningKey,
        task_id: &str,
        proof_hash: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let signature_version = 0;
        let msg = format!("{} | {} | {}", signature_version, task_id, proof_hash);
        let signature = signing_key.sign(msg.as_bytes());
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        (
            signature.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        )
    }

    /// Detects the user's country for network optimization purposes.
    ///
    /// Privacy Note: This only detects the country (2-letter code like "US", "CA", "GB")
    /// and does NOT track precise location, IP address, or any personally identifiable
    /// information. The country information helps the Nexus network route requests to
    /// the nearest servers for better performance and reduced latency.
    ///
    /// The detection is cached for the duration of the program run.
    async fn get_country(&self) -> String {
        if let Some(country) = COUNTRY_CODE.get() {
            return country.clone();
        }

        let country = self.detect_country().await;
        let _ = COUNTRY_CODE.set(country.clone());
        country
    }

    async fn detect_country(&self) -> String {
        // Try Cloudflare first (most reliable)
        if let Ok(country) = self.get_country_from_cloudflare().await {
            return country;
        }

        // Fallback to ipinfo.io
        if let Ok(country) = self.get_country_from_ipinfo().await {
            return country;
        }

        // If we can't detect the country, use the US as a fallback
        "US".to_string()
    }

    async fn get_country_from_cloudflare(&self) -> Result<String, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get("https://cloudflare.com/cdn-cgi/trace")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let text = response.text().await?;

        for line in text.lines() {
            if let Some(country) = line.strip_prefix("loc=") {
                let country = country.trim().to_uppercase();
                if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
                    return Ok(country);
                }
            }
        }

        Err("Country not found in Cloudflare response".into())
    }

    async fn get_country_from_ipinfo(&self) -> Result<String, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get("https://ipinfo.io/country")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let country = response.text().await?;
        let country = country.trim().to_uppercase();

        if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
            Ok(country)
        } else {
            Err("Invalid country code from ipinfo.io".into())
        }
    }
}

#[async_trait::async_trait]
impl Orchestrator for OrchestratorClient {
    fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Get the user ID associated with a wallet address.
    async fn get_user(&self, wallet_address: &str) -> Result<String, OrchestratorError> {
        let wallet_path = urlencoding::encode(wallet_address).into_owned();
        let endpoint = format!("v3/users/{}", wallet_path);
        let user_response: UserResponse = self.get_request(&endpoint).await?;
        Ok(user_response.user_id)
    }

    /// Registers a new user with the orchestrator.
    async fn register_user(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<(), OrchestratorError> {
        let request = RegisterUserRequest {
            uuid: user_id.to_string(),
            wallet_address: wallet_address.to_string(),
        };
        let request_bytes = Self::encode_request(&request);
        self.post_request_no_response("v3/users", request_bytes)
            .await
    }

    /// Registers a new node with the orchestrator.
    async fn register_node(&self, user_id: &str) -> Result<String, OrchestratorError> {
        let request = RegisterNodeRequest {
            node_type: NodeType::CliProver as i32,
            user_id: user_id.to_string(),
        };
        let request_bytes = Self::encode_request(&request);
        let response: RegisterNodeResponse = self.post_request("v3/nodes", request_bytes).await?;
        Ok(response.node_id)
    }

    /// Get the wallet address associated with a node ID.
    async fn get_node(&self, node_id: &str) -> Result<String, OrchestratorError> {
        let endpoint = format!("v3/nodes/{}", node_id);
        let node_response: crate::nexus_orchestrator::GetNodeResponse =
            self.get_request(&endpoint).await?;
        Ok(node_response.wallet_address)
    }

    async fn get_proof_task(
        &self,
        node_id: &str,
        verifying_key: VerifyingKey,
    ) -> Result<Task, OrchestratorError> {
        let request = GetProofTaskRequest {
            node_id: node_id.to_string(),
            node_type: NodeType::CliProver as i32,
            ed25519_public_key: verifying_key.to_bytes().to_vec(),
            max_difficulty: TaskDifficulty::Large as i32,
        };
        let request_bytes = Self::encode_request(&request);
        let response: GetProofTaskResponse = self.post_request("v3/tasks", request_bytes).await?;
        Ok(Task::from(&response))
    }

    async fn submit_proof(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof: Vec<u8>,
        proofs: Vec<Vec<u8>>,
        signing_key: SigningKey,
        num_provers: usize,
        task_type: crate::nexus_orchestrator::TaskType,
        individual_proof_hashes: &[String],
    ) -> Vec<u8> {
        let (program_memory, total_memory) = get_memory_info();
        let flops = estimate_peak_gflops(num_provers);
        let (signature, public_key) = self.create_signature(&signing_key, task_id, proof_hash);

        // Detect country for network optimization (privacy-preserving: only country code, no precise location)
        let location = "US".to_owned();
        let (proof_to_send, proofs_to_send, all_proof_hashes_to_send) =
            OrchestratorClient::select_proof_payload(
                task_type,
                proof,
                proofs,
                individual_proof_hashes,
            );

        let request = SubmitProofRequest {
            task_id: task_id.to_string(),
            node_type: NodeType::CliProver as i32,
            proof_hash: proof_hash.to_string(),
            proof: proof_to_send,
            proofs: proofs_to_send,
            node_telemetry: Some(crate::nexus_orchestrator::NodeTelemetry {
                flops_per_sec: Some(flops as i32),
                memory_used: Some(program_memory),
                memory_capacity: Some(total_memory),
                // Country code for network routing optimization (privacy-preserving)
                location: Some(location),
            }),
            ed25519_public_key: public_key,
            signature,
            all_proof_hashes: all_proof_hashes_to_send,
        };
        let request_bytes = Self::encode_request(&request);
        request_bytes
    }
}
