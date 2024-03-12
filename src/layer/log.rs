use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use motore::{layer::Layer, service, Service};
use tracing::info;

use crate::state::ClientState;

#[derive(Clone)]
pub struct Log<S> {
    inner: S,
}

#[service]
impl<S> Service<ClientState, Request<IncomingBody>> for Log<S>
where
    S: Service<
            ClientState,
            Request<IncomingBody>,
            Response = Response<BoxBody<Bytes, hyper::Error>>,
            Error = hyper::Error,
        >
        + 'static
        + Send
        + Sync,
{
    async fn call(
        &self,
        state: &mut ClientState,
        req: Request<IncomingBody>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if state.parse {
            info!("request: {req:?}");
        }
        let resp = self.inner.call(state, req).await;
        if state.parse {
            info!("response: {resp:?}");
        }
        resp
    }
}

#[derive(Clone)]
pub struct LogLayer;

impl<S> Layer<S> for LogLayer {
    type Service = Log<S>;

    fn layer(self, inner: S) -> Self::Service {
        Log { inner }
    }
}
