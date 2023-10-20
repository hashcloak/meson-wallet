#![allow(non_snake_case)]
use crate::json_rpc::{JsonRequest, JsonResponse};
use crate::meson_util::bindings::{
    BlockingSendUnreliableMessage, GetService, NewClient, NewSession, Register, Shutdown,
};
use crate::{error::MesonError, user_opertaion};
use base64ct::Encoding;
use ethers::prelude::{Address, U256};
use ethers::utils::hex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use serde_json::{json, Number};
use std::{
    ffi::{c_void, CString},
    ops::Add,
};

pub mod bindings;
pub mod meson_provider;

// meson plugin command
pub const ETH_QUERY: u8 = 0x10;
pub const POST_TRANSACTION: u8 = 0x00;
pub const DIRECT_POST: u8 = 0x01;

const MESON_SERVICE: &str = "meson";

// meson plugin currency request
#[derive(Serialize, Deserialize)]
pub struct MesonCurrencyRequest {
    pub Version: i8,
    pub Command: u8,
    pub Ticker: String,
    pub Payload: String,
}

impl MesonCurrencyRequest {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("meson json error")
    }
}

// meson plugin currency response
#[derive(Deserialize)]
pub struct MesonCurrencyResponse {
    pub Version: i8,
    pub Message: String,
    pub Error: String,
}

impl<'a> MesonCurrencyResponse {
    pub fn from_json(raw_response: &[u8]) -> Self {
        let meson_response: MesonCurrencyResponse =
            serde_json::from_slice(raw_response).expect("meson json error");
        meson_response
    }
}

// meson plugin eth query request
#[derive(Serialize)]
pub struct EthQueryRequest {
    pub From: Address,
    pub To: Address,
    pub Value: Number,
    pub Data: String,
}

impl EthQueryRequest {
    pub fn to_json(&self) -> Vec<u8> {
        let json_vec = serde_json::to_vec(self).expect("eth json error");
        //modify_to_go_bigint(&mut json_vec);
        json_vec
    }
}

// meson plugin eth query response
#[derive(Serialize, Deserialize)]
pub struct EthQueryResponse {
    pub Nonce: String,
    pub GasPrice: String,
    pub GasLimit: String,
}

// meson plugin post transaction request
#[derive(Serialize, Deserialize)]
pub struct PostTransactionRequest {
    pub TxHex: String,
}
impl PostTransactionRequest {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("meson json error")
    }
}

// return eth_sendRawTransaction json request
pub fn eth_send_tx_req(raw_tx: &[u8]) -> Vec<u8> {
    let tx = hex::encode(raw_tx);
    let json_req = JsonRequest::new(1, "eth_sendRawTransaction", [tx]);
    serde_json::to_vec(&json_req).unwrap()
}

//pub fn get_send_user_op_json_req()

// encode json request to meson request
pub fn meson_currency_req(ticker: &str, json_request: &[u8]) -> MesonCurrencyRequest {
    let payload = base64ct::Base64::encode_string(json_request);

    MesonCurrencyRequest {
        Version: 0,
        Command: DIRECT_POST,
        Ticker: ticker.to_string(),
        Payload: payload,
    }
}

// query nonce and gas info
pub fn meson_eth_query_req(
    from: &Address,
    to: &Address,
    data: Option<&[u8]>,
    value: U256,
) -> Result<Vec<u8>, MesonError> {
    let from = "0x".to_string() + &hex::encode(from);
    let to = "0x".to_string() + &hex::encode(to);
    let nonce_req = JsonRequest::new(1, "eth_getTransactionCount", [&from, "pending"]);
    let estimate_priority_fee_req = JsonRequest::new(2, "eth_maxPriorityFeePerGas", ());
    let estimate_gas_req = if let Some(data) = data {
        JsonRequest::new(
            3,
            "eth_estimateGas",
            json!([{"from": &from, "to": &to, "value": value, "data": data}]),
        )
    } else {
        JsonRequest::new(
            3,
            "eth_estimateGas",
            json!([{"from": &from, "to": &to, "value": value}]),
        )
    };
    // serde_json::to_vec(&json!([
    //     nonce_req,
    //     estimate_priority_fee_req,
    //     estimate_gas_req
    // ]))
    // .unwrap()
    Ok(serde_json::to_vec(&nonce_req)?)
}

//register on meson through ffi
fn meson_register(path: &str) {
    let configFile = CString::new(path).expect("CString::new failed");
    unsafe {
        Register(configFile.into_raw());
        NewClient(
            CString::new(MESON_SERVICE)
                .expect("CString::new failed")
                .into_raw(),
        );
        NewSession();
        GetService(
            CString::new(MESON_SERVICE)
                .expect("CString::new failed")
                .into_raw(),
        );
    }
}

//send a meson request
pub fn meson_send<R: DeserializeOwned>(mut req: Vec<u8>) -> Result<R, MesonError> {
    unsafe {
        let meson_raw_return = bindings::BlockingSendUnreliableMessage(
            req.as_mut_ptr() as *mut c_void,
            req.len().try_into().expect("len error"),
        );
        let meson_return = &*std::ptr::slice_from_raw_parts_mut(
            meson_raw_return.r0 as *mut u8,
            meson_raw_return.r1.try_into().expect("len error"),
        );

        let mut meson_return: Vec<u8> = meson_return
            .to_vec()
            .into_iter()
            .rev()
            .skip_while(|&x| x == 0)
            .collect();
        meson_return.reverse(); // clear the tailing zeros

        // deserialize to MesonCurrencyResponse
        let meson_response = MesonCurrencyResponse::from_json(&meson_return[..]);
        let error = meson_response.Error;
        if error != "" {
            return Err(MesonError::MesonError(error));
        }

        // deserialize Message to JsonResponse
        let response = meson_response.Message;
        println!("r:{}", response);
        let responses: Vec<JsonResponse> = serde_json::from_str(&response)?;

        let mut v: Vec<Value> = vec![];
        if responses.len() == 1 {
            // single request
            if let Some(e) = &responses[0].error {
                return Err(MesonError::RPCError(e.to_string()));
            } else {
                if let Some(r) = responses[0].result {
                    return Ok(serde_json::from_str(r.get())?);
                }
            }
        } else {
            // batch request
            for res in responses {
                if let Some(e) = &res.error {
                    return Err(MesonError::RPCError(e.to_string()));
                } else {
                    if let Some(r) = res.result {
                        v.push(serde_json::from_str(r.get())?);
                    }
                }
            }
        }
        Ok(serde_json::from_value(Value::Array(v))?)
    }
}

// close meson connection
pub fn meson_close_conn() {
    unsafe {
        Shutdown();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_json() {
        let req = JsonRequest::new(1, "eth_sendRawTransaction", ());
        let a = &serde_json::to_vec(&req).unwrap();
        println!("{:?}", a);
    }
}
