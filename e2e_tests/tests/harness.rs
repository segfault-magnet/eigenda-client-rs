use e2e_tests::kms::Kms;

#[tokio::test]
async fn first_test() {
    let kms = Kms::default().with_show_logs(true).start().await.unwrap();
}
