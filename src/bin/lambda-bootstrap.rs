/// main() for AWS Lambda
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    use lambda_runtime::{run, service_fn};
    run(service_fn(lambda_handler)).await?;
    Ok(())
}

/// Lambda handler
async fn lambda_handler(
    _event: lambda_runtime::LambdaEvent<serde_json::Value>,
) -> Result<serde_json::Value, lambda_runtime::Error> {
    Ok(serde_json::json!({}))
}
