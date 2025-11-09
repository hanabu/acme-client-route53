/// Set region as "us-east-1", etc. or None for default region
pub async fn aws_config_from_env(
    region: impl aws_config::meta::region::ProvideRegion + 'static,
) -> aws_config::SdkConfig {
    if region.region().await.is_some() {
        // Specified region
        aws_config::from_env().region(region).load().await
    } else {
        // default region
        aws_config::from_env().load().await
    }
}
