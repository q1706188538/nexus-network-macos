//! Error handling for the orchestrator module

use prost::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[allow(non_snake_case)] // used for json parsing
#[derive(Serialize, Deserialize)]
struct RawError {
    name: String,
    message: String,
    httpCode: u16,
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// Failed to decode a Protobuf message from the server
    #[error("Decoding error: {0}")]
    Decode(#[from] DecodeError),

    /// Reqwest error, typically related to network issues or request failures.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// An error occurred while processing the request.
    #[error("HTTP error with status {status}: {message}")]
    Http { status: u16, message: String },

    /// Rate limited by the server (429)
    #[error("Rate limited: retry after {retry_after} seconds")]
    RateLimited { retry_after: u64 },
}

impl OrchestratorError {
    pub async fn from_response(response: reqwest::Response) -> OrchestratorError {
        let status = response.status().as_u16();
        // 429专用处理
        if status == 429 {
            let retry_after = response.headers().get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<f64>().ok())
                .map(|f| if f > 0.0 { f as u64 } else { 0 })
                .unwrap_or(0);
            return OrchestratorError::RateLimited { retry_after };
        }
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read response text".to_string());

        OrchestratorError::Http { status, message }
    }

    pub fn to_pretty(&self) -> Option<String> {
        match self {
            Self::Http {
                status: _,
                message: msg,
            } => {
                if let Ok(parsed) = serde_json::from_str::<RawError>(msg) {
                    if let Ok(stringified) = serde_json::to_string_pretty(&parsed) {
                        return Some(stringified);
                    }
                }

                None
            }
            _ => None,
        }
    }
}
