#![allow(clippy::manual_async_fn)]

use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use motore::{service, Service};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, error};

use crate::state::State;
use crate::util::{self, create_ssl_connection};

#[derive(Clone)]
pub struct HttpClient {
    addr: String,
    host: String,
    is_secure: bool,
}

impl HttpClient {
    pub fn new(addr: String, host: String, is_secure: bool) -> Self {
        Self {
            addr,
            host,
            is_secure,
        }
    }
}

#[service]
impl Service<State, Request<IncomingBody>> for HttpClient {
    async fn call(
        &self,
        state: &mut State,
        req: Request<IncomingBody>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if self.is_secure {
            let sni = state.get_sni(&self.host);

            if let Ok(stream) = create_ssl_connection(&self.addr, sni)
                .await
                .inspect_err(|e| error!("create ssl stream failed: {e}"))
            {
                return http_request(req, stream).await;
            }
        } else if let Ok(stream) = TcpStream::connect(&self.addr)
            .await
            .inspect_err(|e| error!("create stream failed: {e}"))
        {
            return http_request(req, stream).await;
        }

        let mut resp = Response::new(util::full("connect http failed"));
        *resp.status_mut() = StatusCode::NOT_ACCEPTABLE;
        Ok(resp)
    }
}

async fn http_request<T>(
    req: Request<IncomingBody>,
    stream: T,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!("connect success");

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move { conn.await.inspect_err(|e| error!("Connection failed: {e}")) });

    let resp = sender.send_request(req).await?;
    let resp = resp.map(|b| b.boxed());

    Ok(resp)
}

// pub type RequestFuture = Pin<Box<dyn Future<Output = Result<Request<IncomingBody>, ()>> + Send>>;
// pub type ResponseFuture =
//     Pin<Box<dyn Future<Output = Result<Response<BoxBody<Bytes, hyper::Error>>, ()>> + Send>>;
// pub struct PrintReq;

// impl Service<Request<IncomingBody>> for PrintReq {
//     type Response = Request<IncomingBody>;
//     type Error = ();
//     type Future = RequestFuture;

//     fn call(&self, req: Request<IncomingBody>) -> Self::Future {
//         Box::pin(async move {
//             info!("{:?}", req);
//             Ok(req)
//         })
//     }
// }

// pub struct PrintResp;

// impl Service<Response<BoxBody<Bytes, hyper::Error>>> for PrintResp {
//     type Response = Response<BoxBody<Bytes, hyper::Error>>;
//     type Error = ();
//     type Future = ResponseFuture;

//     fn call(&self, resp: Response<BoxBody<Bytes, hyper::Error>>) -> Self::Future {
//         Box::pin(async move {
//             info!("{:?}", resp);
//             Ok(resp)
//         })
//     }
// }
