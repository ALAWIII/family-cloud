use family_cloud::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // should success
    run().await
}
