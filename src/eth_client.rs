use bytes::Bytes;
use ethereum_types::{Address, U256};
/// This client is inspired in ethrex EthClient https://github.com/lambdaclass/ethrex/blob/main/crates/l2/utils/eth_client/mod.rs
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::errors::EthClientError;

/// Request ID for the RPC
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RpcRequestId {
    Number(u64),
    String(String),
}

/// Response for a successful RPC request
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcSuccessResponse {
    pub(crate) id: RpcRequestId,
    pub(crate) jsonrpc: String,
    pub(crate) result: Value,
}

/// Metadata for an RPC error
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcErrorMetadata {
    pub(crate) code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<String>,
    pub(crate) message: String,
}

/// Response for an RPC error
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcErrorResponse {
    pub(crate) id: RpcRequestId,
    pub(crate) jsonrpc: String,
    pub(crate) error: RpcErrorMetadata,
}

/// Response for an RPC request
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum RpcResponse {
    Success(RpcSuccessResponse),
    Error(RpcErrorResponse),
}

/// Request for the RPC
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RpcRequest {
    pub(crate) id: RpcRequestId,
    pub(crate) jsonrpc: String,
    pub(crate) method: String,
    pub(crate) params: Option<Vec<Value>>,
}

/// Client for interacting with an Ethereum node
#[derive(Debug, Clone)]
pub(crate) struct EthClient {
    client: Client,
    pub(crate) url: String,
}

impl EthClient {
    /// Creates a new EthClient
    pub(crate) fn new(url: &str) -> Self {
        Self {
            client: Client::new(),
            url: url.to_string(),
        }
    }

    /// Sends a request to the Ethereum node
    async fn send_request(&self, request: RpcRequest) -> Result<RpcResponse, EthClientError> {
        self.client
            .post(&self.url)
            .header("content-type", "application/json")
            .body(serde_json::ser::to_string(&request).map_err(|error| {
                EthClientError::FailedToSerializeRequestBody(format!("{error}: {request:?}"))
            })?)
            .send()
            .await?
            .json::<RpcResponse>()
            .await
            .map_err(EthClientError::from)
    }

    /// Gets the latest block number
    pub(crate) async fn get_block_number(&self) -> Result<U256, EthClientError> {
        let request = RpcRequest {
            id: RpcRequestId::Number(1),
            jsonrpc: "2.0".to_string(),
            method: "eth_blockNumber".to_string(),
            params: None,
        };

        match self.send_request(request).await {
            Ok(RpcResponse::Success(result)) => {
                serde_json::from_value(result.result).map_err(EthClientError::SerdeJSON)
            }
            Ok(RpcResponse::Error(error_response)) => {
                Err(EthClientError::RPC(error_response.error.message))
            }
            Err(error) => Err(error),
        }
    }

    /// Calls a contract
    pub(crate) async fn call(
        &self,
        to: Address,
        calldata: Bytes,
        block: Option<u64>,
    ) -> Result<String, EthClientError> {
        let request = RpcRequest {
            id: RpcRequestId::Number(1),
            jsonrpc: "2.0".to_string(),
            method: "eth_call".to_string(),
            params: Some(vec![
                json!({
                    "to": format!("{:#x}",to),
                    "input": format!("0x{:#x}", calldata),
                    "value": format!("{:#x}", 0),
                    "from": format!("{:#x}", Address::zero()),
                }),
                json!(match block {
                    Some(block) => format!("{:#x}", block),
                    None => "latest".to_string(),
                }),
            ]),
        };

        match self.send_request(request).await {
            Ok(RpcResponse::Success(result)) => {
                serde_json::from_value(result.result).map_err(EthClientError::SerdeJSON)
            }
            Ok(RpcResponse::Error(error_response)) => {
                Err(EthClientError::RPC(error_response.error.message))
            }
            Err(error) => Err(error),
        }
    }
}
