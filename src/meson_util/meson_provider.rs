use crate::error::MesonError;
use crate::json_rpc::JsonRequest;
use crate::meson_util::{meson_close_conn, meson_currency_req, meson_register, meson_send};
use async_trait::async_trait;
use ethers::prelude::JsonRpcClient;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug)]
pub struct MesonProvider<'a> {
    id: AtomicU64,
    meson_setting_path: &'a Path,
    ticker: &'a str,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> JsonRpcClient for MesonProvider<'a> {
    type Error = MesonError;

    // send a request through meson
    async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, Self::Error> {
        let next_id = self.id.fetch_add(1, Ordering::SeqCst);
        let payload = JsonRequest::new(next_id, method, params);
        let json_req = serde_json::to_vec(&payload)?;
        let meson_req = meson_currency_req(self.ticker, &json_req);
        Ok(meson_send(meson_req.to_json())?)
    }
}

// close meson connection when provider is dropped
impl<'a> Drop for MesonProvider<'a> {
    fn drop(&mut self) {
        meson_close_conn();
    }
}

impl<'a> MesonProvider<'a> {
    // initialize without dropping the previous instance will cause error
    pub fn new(meson_setting_path: &'a Path, ticker: &'a str) -> Result<Self, MesonError> {
        meson_register(
            meson_setting_path
                .to_str()
                .ok_or(MesonError::MesonError("error".to_string()))?,
        );

        Ok(Self {
            id: AtomicU64::new(1),
            meson_setting_path,
            ticker,
        })
    }

    // send a batch request through meson
    async fn batch_request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        methods: Vec<&str>,
        params: Vec<T>,
    ) -> Result<R, MesonError> {
        let it = methods.into_iter().zip(params.into_iter());
        let mut payloads = vec![];
        for (_, (method, param)) in it.enumerate() {
            let next_id = self.id.fetch_add(1, Ordering::SeqCst);
            let payload = JsonRequest::new(next_id, method, param);
            payloads.push(payload);
        }

        let json_req = serde_json::to_vec(&payloads)?;
        let meson_req = meson_currency_req(self.ticker, &json_req);
        Ok(meson_send(meson_req.to_json())?)
    }
}
