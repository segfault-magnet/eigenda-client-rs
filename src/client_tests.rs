/// EigenDA Client tests are ignored by default, because they require a remote dependency,
/// which may not always be available, causing tests to be flaky.
/// To run these tests, use the following command:
/// `cargo test client_tests -- --ignored`
#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use crate::{
        client::GetBlobData,
        config::{EigenConfig, EigenSecrets, PrivateKey},
        errors::{CommunicationError, EigenClientError},
        EigenClient,
    };
    use backon::{ConstantBuilder, Retryable};
    use serial_test::serial;

    use crate::blob_info::BlobInfo;

    impl EigenClient {
        pub(crate) async fn get_blob_data(
            &self,
            blob_id: BlobInfo,
        ) -> Result<Option<Vec<u8>>, EigenClientError> {
            self.client.get_blob_data(blob_id).await
        }

        pub(crate) async fn get_commitment(
            &self,
            blob_id: &str,
        ) -> Result<Option<BlobInfo>, EigenClientError> {
            self.client.get_commitment(blob_id).await
        }
    }

    const STATUS_QUERY_TIMEOUT: u64 = 1800000; // 30 minutes
    const STATUS_QUERY_INTERVAL: u64 = 5; // 5 ms

    async fn get_blob_info(
        client: &EigenClient,
        blob_id: &str,
    ) -> Result<BlobInfo, EigenClientError> {
        let blob_info = (|| async {
            let blob_info = client.get_commitment(blob_id).await?;
            if blob_info.is_none() {
                return Err(EigenClientError::Communication(
                    CommunicationError::FailedToGetBlobData,
                ));
            }
            Ok(blob_info.unwrap())
        })
        .retry(
            &ConstantBuilder::default()
                .with_delay(Duration::from_millis(STATUS_QUERY_INTERVAL))
                .with_max_times((STATUS_QUERY_TIMEOUT / STATUS_QUERY_INTERVAL) as usize),
        )
        .when(|e| {
            matches!(
                e,
                EigenClientError::Communication(CommunicationError::FailedToGetBlobData)
            )
        })
        .await?;

        Ok(blob_info)
    }

    #[derive(Debug, Clone)]
    struct MockGetBlobData;

    #[async_trait::async_trait]
    impl GetBlobData for MockGetBlobData {
        async fn get_blob_data(
            &self,
            _input: &'_ str,
        ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }

        fn clone_boxed(&self) -> Box<dyn GetBlobData> {
            Box::new(self.clone())
        }
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_non_auth_dispersal() {
        let config = EigenConfig {
            disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
            settlement_layer_confirmation_depth: 0,
            eigenda_eth_rpc: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            eigenda_svc_manager_address: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b".to_string(),
            wait_for_finalization: false,
            authenticated: false,
            g1_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            g2_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
        };
        let secrets = EigenSecrets {
            private_key: PrivateKey::from_str(
                "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6",
            )
            .unwrap(),
        };
        let client = EigenClient::new(config.clone(), secrets, Box::new(MockGetBlobData))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();

        let blob_info = get_blob_info(&client, &result).await.unwrap();
        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert_eq!(expected_inclusion_data, actual_inclusion_data);
        let retrieved_data = client.get_blob_data(blob_info).await.unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_auth_dispersal() {
        let config = EigenConfig {
            disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
            settlement_layer_confirmation_depth: 0,
            eigenda_eth_rpc: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            eigenda_svc_manager_address: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b".to_string(),
            wait_for_finalization: false,
            authenticated: true,
            g1_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            g2_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
        };
        let secrets = EigenSecrets {
            private_key: PrivateKey::from_str(
                "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6",
            )
            .unwrap(),
        };
        let client = EigenClient::new(config.clone(), secrets, Box::new(MockGetBlobData))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert_eq!(expected_inclusion_data, actual_inclusion_data);
        let retrieved_data = client.get_blob_data(blob_info).await.unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_wait_for_finalization() {
        let config = EigenConfig {
            disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
            wait_for_finalization: true,
            authenticated: true,
            g1_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            g2_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
            settlement_layer_confirmation_depth: 0,
            eigenda_eth_rpc: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            eigenda_svc_manager_address: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b".to_string(),
        };
        let secrets = EigenSecrets {
            private_key: PrivateKey::from_str(
                "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6",
            )
            .unwrap(),
        };
        let client = EigenClient::new(config.clone(), secrets, Box::new(MockGetBlobData))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert_eq!(expected_inclusion_data, actual_inclusion_data);
        let retrieved_data = client.get_blob_data(blob_info).await.unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_settlement_layer_confirmation_depth() {
        let config = EigenConfig {
            disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
            settlement_layer_confirmation_depth: 5,
            eigenda_eth_rpc: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            eigenda_svc_manager_address: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b".to_string(),
            wait_for_finalization: false,
            authenticated: false,
            g1_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            g2_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
        };
        let secrets = EigenSecrets {
            private_key: PrivateKey::from_str(
                "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6",
            )
            .unwrap(),
        };
        let client = EigenClient::new(config.clone(), secrets, Box::new(MockGetBlobData))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert_eq!(expected_inclusion_data, actual_inclusion_data);
        let retrieved_data = client.get_blob_data(blob_info).await.unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }

    #[ignore = "depends on external RPC"]
    #[tokio::test]
    #[serial]
    async fn test_auth_dispersal_settlement_layer_confirmation_depth() {
        let config = EigenConfig {
            disperser_rpc: "https://disperser-holesky.eigenda.xyz:443".to_string(),
            settlement_layer_confirmation_depth: 5,
            eigenda_eth_rpc: "https://ethereum-holesky-rpc.publicnode.com".to_string(),
            eigenda_svc_manager_address: "0xD4A7E1Bd8015057293f0D0A557088c286942e84b".to_string(),
            wait_for_finalization: false,
            authenticated: true,
            g1_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g1.point".to_string(),
            g2_url: "https://github.com/Layr-Labs/eigenda-proxy/raw/2fd70b99ef5bf137d7bbca3461cf9e1f2c899451/resources/g2.point.powerOf2".to_string(),
        };
        let secrets = EigenSecrets {
            private_key: PrivateKey::from_str(
                "d08aa7ae1bb5ddd46c3c2d8cdb5894ab9f54dec467233686ca42629e826ac4c6",
            )
            .unwrap(),
        };
        let client = EigenClient::new(config.clone(), secrets, Box::new(MockGetBlobData))
            .await
            .unwrap();
        let data = vec![1; 20];
        let result = client.dispatch_blob(data.clone()).await.unwrap();
        let blob_info = get_blob_info(&client, &result).await.unwrap();

        let expected_inclusion_data = blob_info.clone().blob_verification_proof.inclusion_proof;
        let actual_inclusion_data = client.get_inclusion_data(&result).await.unwrap().unwrap();
        assert_eq!(expected_inclusion_data, actual_inclusion_data);
        let retrieved_data = client.get_blob_data(blob_info).await.unwrap();
        assert_eq!(retrieved_data.unwrap(), data);
    }
}
