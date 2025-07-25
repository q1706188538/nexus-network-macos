use crate::environment::Environment;
use crate::orchestrator::error::OrchestratorError;
use crate::task::Task;
use ed25519_dalek::{SigningKey, VerifyingKey};

mod client;
pub use client::{
    OrchestratorClient, DUPLICATE_TASKS_FETCHED, FAILED_SUBMISSIONS, SUCCESSFUL_SUBMISSIONS,
    TOTAL_TASKS_FETCHED, UNIQUE_TASKS_FETCHED,
};
pub mod error;

#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait Orchestrator: Send + Sync {
    fn environment(&self) -> &Environment;

    /// Get the user ID associated with a wallet address.
    async fn get_user(&self, wallet_address: &str) -> Result<String, OrchestratorError>;

    /// Registers a new user with the orchestrator.
    async fn register_user(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<(), OrchestratorError>;

    /// Registers a new node with the orchestrator.
    async fn register_node(&self, user_id: &str) -> Result<String, OrchestratorError>;

    /// Get the list of tasks currently assigned to the node.
    async fn get_tasks(&self, node_id: &str) -> Result<Vec<Task>, OrchestratorError>;

    /// Request a new proof task for the node.
    async fn get_proof_task(
        &self,
        node_id: &str,
        verifying_key: VerifyingKey,
    ) -> Result<Task, OrchestratorError>;

    /// Submits a proof to the orchestrator.
    async fn submit_proof(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof: Vec<u8>,
        signing_key: SigningKey,
        num_provers: usize,
    ) -> Result<(), OrchestratorError>;

    /// Recreates the orchestrator client with a new proxy.
    fn recreate_with_new_proxy(&self) -> Box<dyn Orchestrator>;
}
