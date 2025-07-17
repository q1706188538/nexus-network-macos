//! Nexus Orchestrator Client
//!
//! A client for the Nexus Orchestrator, allowing for proof task retrieval and submission.

use crate::environment::Environment;
use crate::nexus_orchestrator::{
    GetProofTaskRequest, GetProofTaskResponse, GetTasksResponse, NodeType, RegisterNodeRequest,
    RegisterNodeResponse, RegisterUserRequest, SubmitProofRequest, UserResponse,
};
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::system::{estimate_peak_gflops, get_memory_info};
use crate::task::Task;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use prost::Message;
use reqwest::{Client, ClientBuilder, Response, Proxy};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;
use rand::{distributions::Alphanumeric, Rng};
use tracing::trace;

// Global counters for task submissions
pub static SUCCESSFUL_SUBMISSIONS: AtomicUsize = AtomicUsize::new(0);
pub static FAILED_SUBMISSIONS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_TASKS_FETCHED: AtomicUsize = AtomicUsize::new(0);
pub static DUPLICATE_TASKS_FETCHED: AtomicUsize = AtomicUsize::new(0);
pub static UNIQUE_TASKS_FETCHED: AtomicUsize = AtomicUsize::new(0);

// Privacy-preserving country detection for network optimization.
// Only stores 2-letter country codes (e.g., "US", "CA", "GB") to help route
// requests to the nearest Nexus network servers for better performance.
// No precise location, IP addresses, or personal data is collected or stored.
static COUNTRY_CODE: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    client: Client,
    environment: Environment,
    proxy_url: Option<String>,
    proxy_user_pwd: Option<String>,
}

impl OrchestratorClient {
    pub fn new(environment: Environment, proxy_url: Option<String>, proxy_user_pwd: Option<String>) -> Self {
        let mut client_builder = ClientBuilder::new()
            .timeout(Duration::from_secs(30)) // 增加超时以适应潜在的慢代理
            .no_proxy(); // 禁用系统代理，确保我们的设置是唯一的

        if let (Some(url), Some(user_pwd)) = (proxy_url.clone(), proxy_user_pwd.clone()) {
            if !url.is_empty() {
                let proxy_str = Self::generate_proxy_url(&url, &user_pwd);
                
                // 为所有协议创建同一个代理
                let proxy = Proxy::all(proxy_str).expect("Failed to create proxy");
                
                client_builder = client_builder.proxy(proxy);
            }
        }

        Self {
            client: client_builder.build().expect("Failed to create HTTP client"),
            environment,
            proxy_url,
            proxy_user_pwd,
        }
    }

    pub fn generate_proxy_url(base_url: &str, user_pwd: &str) -> String {
        if base_url.contains('@') {
            // If the base_url contains a username, use it directly.
            // Expected format: "username@hostname:port"
            let parts: Vec<&str> = base_url.split('@').collect();
            if parts.len() == 2 {
                let user = parts[0];
                let host_port = parts[1];
                return format!("http://{}:{}@{}", user, user_pwd, host_port);
            }
        }

        // Original logic for roxproxy
        let random_part: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let sessid = format!("hk{}", random_part);
        let proxy_user = format!("user-roxadmin-region-hk-sessid-{}-sesstime-1-keep-true", sessid);
        format!("http://{}:{}@{}", proxy_user, user_pwd, base_url)
    }

    pub fn proxy_url_cloned(&self) -> Option<String> {
        self.proxy_url.clone()
    }

    pub fn proxy_user_pwd_cloned(&self) -> Option<String> {
        self.proxy_user_pwd.clone()
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
        let response = self.client.get(&url).send().await?;

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
        let url = self.build_url(endpoint);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        // Manually handle the response to log the raw text
        let status = response.status();
        let response_text = response.text().await.unwrap_or_else(|e| format!("[网络错误] 无法读取响应文本: {}", e));

        println!("[任务提交] 端点: {}, 状态码: {}, 原始响应: {}", endpoint, status, response_text);

        if status.is_success() {
            SUCCESSFUL_SUBMISSIONS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        } else {
            FAILED_SUBMISSIONS.fetch_add(1, Ordering::SeqCst);
            Err(OrchestratorError::Http { status: status.as_u16(), message: response_text })
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

    async fn get_tasks(&self, node_id: &str) -> Result<Vec<Task>, OrchestratorError> {
        let response: GetTasksResponse = self.get_request(&format!("v3/tasks/{}", node_id)).await?;
        let tasks = response.tasks.iter().map(Task::from).collect();
        Ok(tasks)
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
        signing_key: SigningKey,
        num_provers: usize,
    ) -> Result<(), OrchestratorError> {
        let (program_memory, total_memory) = get_memory_info();
        let flops = estimate_peak_gflops(num_provers);
        let (signature, public_key) = self.create_signature(&signing_key, task_id, proof_hash);

        // Detect country for network optimization (privacy-preserving: only country code, no precise location)
        let location = self.get_country().await;
        let request = SubmitProofRequest {
            task_id: task_id.to_string(),
            node_type: NodeType::CliProver as i32,
            proof_hash: proof_hash.to_string(),
            proof,
            node_telemetry: Some(crate::nexus_orchestrator::NodeTelemetry {
                flops_per_sec: Some(flops as i32),
                memory_used: Some(program_memory),
                memory_capacity: Some(total_memory),
                // Country code for network routing optimization (privacy-preserving)
                location: Some(location),
            }),
            ed25519_public_key: public_key,
            signature,
        };
        let request_bytes = Self::encode_request(&request);

        self.post_request_no_response("v3/tasks/submit", request_bytes)
            .await
    }



    fn recreate_with_new_proxy(&self) -> Box<dyn Orchestrator> {
        Box::new(OrchestratorClient::new(
            self.environment.clone(),
            self.proxy_url.clone(),
            self.proxy_user_pwd.clone(),
        ))
    }
}

#[cfg(test)]
/// These are ignored by default since they require a live orchestrator to run.
mod live_orchestrator_tests {
    use crate::environment::Environment;
    use crate::orchestrator::Orchestrator;

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should register a new user with the orchestrator.
    async fn test_register_user() {
        let client = super::OrchestratorClient::new(Environment::Beta, None, None);
        // UUIDv4 for the user ID
        let user_id = uuid::Uuid::new_v4().to_string();
        let wallet_address = "0x1234567890abcdef1234567890cbaabc12345678"; // Example wallet address
        match client.register_user(&user_id, wallet_address).await {
            Ok(_) => println!("User registered successfully: {}", user_id),
            Err(e) => panic!("Failed to register user: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should register a new node to an existing user.
    async fn test_register_node() {
        let client = super::OrchestratorClient::new(Environment::Beta, None, None);
        let user_id = "78db0be7-f603-4511-9576-c660f3c58395";
        match client.register_node(user_id).await {
            Ok(node_id) => println!("Node registered successfully: {}", node_id),
            Err(e) => panic!("Failed to register node: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return a new proof task for the node.
    async fn test_get_proof_task() {
        let client = super::OrchestratorClient::new(Environment::Beta, None, None);
        let node_id = "5880437"; // Example node ID
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let result = client.get_proof_task(node_id, verifying_key).await;
        match result {
            Ok(task) => {
                println!("Retrieved task: {:?}", task);
            }
            Err(e) => {
                panic!("Failed to get proof task: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the list of existing tasks for the node.
    async fn test_get_tasks() {
        let client = super::OrchestratorClient::new(Environment::Beta, None, None);
        let node_id = "5880437"; // Example node ID
        match client.get_tasks(node_id).await {
            Ok(tasks) => {
                println!("Retrieved {} tasks for node {}", tasks.len(), node_id);
                for task in &tasks {
                    println!("Task: {}", task);
                }
            }
            Err(e) => {
                panic!("Failed to get tasks: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the user ID associated with a previously-registered wallet address.
    async fn test_get_user() {
        let client = super::OrchestratorClient::new(Environment::Beta, None, None);
        let wallet_address = "0x52908400098527886E0F7030069857D2E4169EE8";
        match client.get_user(wallet_address).await {
            Ok(user_id) => {
                println!("User ID for wallet {}: {}", wallet_address, user_id);
                assert_eq!(user_id, "e3c62f51-e566-4f9e-bccb-be9f8cb474be");
            }
            Err(e) => panic!("Failed to get user ID: {}", e),
        }
    }

    #[tokio::test]
    /// Should detect country using Cloudflare/fallback services.
    async fn test_country_detection() {
        let client = super::OrchestratorClient::new(Environment::Beta, None, None);
        let country = client.get_country().await;

        println!("Detected country: {}", country);

        // Should be a valid 2-letter country code
        assert_eq!(country.len(), 2);
        assert!(country.chars().all(|c| c.is_ascii_uppercase()));
    }
}
