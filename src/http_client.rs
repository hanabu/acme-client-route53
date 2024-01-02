use hyper::{body::Body, Request, Response};

type Connector = hyper_tls::HttpsConnector<hyper::client::connect::HttpConnector>;
//type HyperClient = hyper::Client<Connector>;

pub(crate) struct HyperTlsClient(hyper::Client<Connector>);

impl HyperTlsClient {
    pub(crate) fn new() -> Self {
        let hyper_connector = Connector::new();
        Self(hyper::Client::builder().build(hyper_connector))
    }

    pub(crate) fn new_boxed() -> Box<Self> {
        Box::new(Self::new())
    }
}

impl instant_acme::HttpClient for HyperTlsClient {
    fn request(
        &self,
        req: Request<Body>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = hyper::Result<Response<Body>>> + Send>>
    {
        Box::pin(<hyper::Client<Connector>>::request(&self.0, req))
    }
}

/// Set region as "us-east-1", etc. or None for default region
pub async fn aws_config_from_env(
    region: impl aws_config::meta::region::ProvideRegion + 'static,
) -> aws_config::SdkConfig {
    use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;

    let hyper_connector = hyper_tls::HttpsConnector::new();
    let hyper_client = HyperClientBuilder::new().build(hyper_connector);

    if region.region().await.is_some() {
        // Specified region
        aws_config::from_env()
            .region(region)
            .http_client(hyper_client)
            .load()
            .await
    } else {
        // default region
        aws_config::from_env()
            .http_client(hyper_client)
            .load()
            .await
    }
}
