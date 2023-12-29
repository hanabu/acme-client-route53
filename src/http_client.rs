use hyper::{body::Body, Request, Response};

type Connector = hyper_tls::HttpsConnector<hyper::client::connect::HttpConnector>;
type HyperClient = hyper::Client<Connector>;

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
        let hyper_connector = hyper_tls::HttpsConnector::new();
        Box::pin(<hyper::Client<Connector>>::request(&self.0, req))
    }
}
