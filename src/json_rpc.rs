use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};
use std::fmt;

fn is_zst<T>(_t: &T) -> bool {
    std::mem::size_of::<T>() == 0
}

#[derive(Serialize, Deserialize, Debug)]
/// A JSON-RPC request
pub struct JsonRequest<'a, T> {
    id: u64,
    jsonrpc: &'a str,
    method: &'a str,
    #[serde(skip_serializing_if = "is_zst")]
    params: T,
}

impl<'a, T> JsonRequest<'a, T> {
    /// Creates a new JSON RPC request
    pub fn new(id: u64, method: &'a str, params: T) -> Self {
        Self {
            id,
            jsonrpc: "2.0",
            method,
            params,
        }
    }
}

#[derive(Deserialize, Debug)]
/// A JSON-RPC response
pub struct JsonResponse<'a> {
    pub id: u64,
    pub jsonrpc: &'a str,
    pub error: Option<JsonRpcError>,
    pub result: Option<&'a RawValue>,
}

#[derive(Deserialize, Debug, Clone)]
/// A JSON-RPC 2.0 error
pub struct JsonRpcError {
    /// The error code
    pub code: i64,
    /// The error message
    pub message: String,
    /// Additional data
    pub data: Option<Value>,
}

impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(code: {}, message: {}, data: {:?})",
            self.code, self.message, self.data
        )
    }
}
