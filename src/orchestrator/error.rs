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

    /// Request timed out
    #[error("Request timeout after {seconds} seconds")]
    Timeout { seconds: u64 },  // 新增超时错误变体

    /// Maximum retries exceeded
    #[error("Maximum retries ({retries}) exceeded")]
    MaxRetriesExceeded { retries: usize },  // 新增重试次数超限错误
}

impl OrchestratorError {
    pub async fn from_response(response: reqwest::Response) -> OrchestratorError {
        let status = response.status().as_u16();
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read response text".to_string());

        OrchestratorError::Http { status, message }
    }
    /// 提取HTTP错误消息（仅当错误类型为Http时有效）
    pub fn http_message(&self) -> Option<&str> {
        match self {
            OrchestratorError::Http { message, .. } => Some(message),
            _ => None,
        }
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
