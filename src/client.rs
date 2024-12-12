use crate::errors::EigenClientError;

use super::{
    config::{EigenConfig, EigenSecrets},
    sdk::RawEigenClient,
};
use async_trait::async_trait;
use secp256k1::SecretKey;
use secrecy::ExposeSecret;
use std::error::Error;
use std::{str::FromStr, sync::Arc};

#[async_trait]
pub trait GetBlobData: Clone + std::fmt::Debug + Send + Sync {
    async fn call(&self, input: &str) -> Result<Option<Vec<u8>>, Box<dyn Error + Send + Sync>>;
}
/// EigenClient is a client for the Eigen DA service.
#[derive(Debug, Clone)]
pub struct EigenClient<T: GetBlobData> {
    pub(crate) client: Arc<RawEigenClient<T>>,
}

impl<T: GetBlobData> EigenClient<T> {
    pub async fn new(
        config: EigenConfig,
        secrets: EigenSecrets,
        get_blob_data: Box<T>,
    ) -> Result<Self, EigenClientError> {
        let private_key = SecretKey::from_str(secrets.private_key.0.expose_secret().as_str())?;

        let client = RawEigenClient::new(private_key, config, get_blob_data).await?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    pub async fn dispatch_blob(&self, data: Vec<u8>) -> Result<String, EigenClientError> {
        let blob_id = self.client.dispatch_blob(data).await?;

        Ok(blob_id)
    }

    pub async fn get_inclusion_data(
        &self,
        blob_id: &str,
    ) -> Result<Option<Vec<u8>>, EigenClientError> {
        let inclusion_data = self.client.get_inclusion_data(blob_id).await?;
        Ok(inclusion_data)
    }

    pub fn blob_size_limit(&self) -> Option<usize> {
        Some(RawEigenClient::<T>::blob_size_limit())
    }
}
