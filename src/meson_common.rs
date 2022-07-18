use ethers::prelude::{Address, U256};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use serde_json::Number;

pub const EthQuery: u8 = 0x10;
pub const PostTransaction: u8 = 0x00;

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

#[derive(Serialize, Deserialize)]
pub struct MesonCurrencyResponse {
    pub Version: i8,
    pub Message: String,
    pub Error: String,
}

impl MesonCurrencyResponse {
    pub fn from_json(raw_response: &[u8]) -> Self {
        let meson_response: MesonCurrencyResponse =
            serde_json::from_slice(raw_response).expect("meson json error");
        meson_response
    }
}

#[derive(Serialize)]
pub struct EthQueryRequest {
    pub From: Address,
    pub To: Address,
    pub Value: Number,
    pub Data: String,
}

impl EthQueryRequest {
    pub fn to_json(&self) -> Vec<u8> {
        let mut json_vec = serde_json::to_vec(self).expect("eth json error");
        //modify_to_go_bigint(&mut json_vec);
        json_vec
    }
}

//had to modify the json query since serde_json can't treat U256 as a json Number
//maybe consider impliment a custom json serializer
fn modify_to_go_bigint(json_vec: &mut Vec<u8>) {
    assert_eq!(&json_vec[104..109], &[86, 97, 108, 117, 101]); //assert "Value" position
    let mut begin_pos = 111;
    let mut count = 0;
    while count < 2 {
        if json_vec[begin_pos] == 34u8 {
            count += 1;
            json_vec.remove(begin_pos);
        }
        begin_pos += 1;
    }
}
#[derive(Serialize, Deserialize)]
pub struct EthQueryResponse {
    pub Nonce: String,
    pub GasPrice: String,
    pub GasLimit: String,
}

impl EthQueryResponse {
    pub fn from_str(query_response: &str) -> Self {
        let eth_query: EthQueryResponse =
            serde_json::from_str(query_response).expect("eth json error");
        eth_query
    }
}

#[derive(Serialize, Deserialize)]
pub struct PostTransactionRequest {
    pub TxHex: String,
}
impl PostTransactionRequest {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("meson json error")
    }
}
