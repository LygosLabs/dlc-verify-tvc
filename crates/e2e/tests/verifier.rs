#![allow(missing_docs, clippy::unwrap_used)]

use e2e::TestArgs;

#[tokio::test]
async fn health_and_version() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let health: serde_json::Value = client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(health["status"], "healthy");

        let version: serde_json::Value = client
            .get(format!("{}/version", test_args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(version["name"], "dlc-verify-tvc");
        assert_eq!(version["egressRequired"], false);
    }
    e2e::Builder::new().execute(test).await;
}
