use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::service::Service;
use hyper::StatusCode;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, error, info};

use crate::util::{self, get_ssl_connection};

pub type RequestFuture = Pin<Box<dyn Future<Output = Result<Request<IncomingBody>, ()>> + Send>>;
pub type ResponseFuture =
    Pin<Box<dyn Future<Output = Result<Response<BoxBody<Bytes, hyper::Error>>, ()>> + Send>>;

pub struct HttpsClient {
    pub addr: String,
    pub sni: String,
}

impl Service<Request<IncomingBody>> for HttpsClient {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        Box::pin(https_request(
            req,
            self.addr.clone(),
            self.sni.clone(),
            Some(PrintReq),
            Some(PrintResp),
        ))
    }
}

async fn https_request<BS, AS>(
    req: Request<hyper::body::Incoming>,
    addr: String,
    sni: String,
    before: Option<BS>,
    after: Option<AS>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    BS: Service<Request<IncomingBody>, Future = RequestFuture>,
    AS: Service<Response<BoxBody<Bytes, hyper::Error>>, Future = ResponseFuture>,
{
    match get_ssl_connection(addr, &sni).await {
        Ok(stream) => http_request(req, stream, before, after).await,
        Err(e) => {
            error!("connect https failed: {e}");
            let mut resp = Response::new(util::full("connect https failed"));
            *resp.status_mut() = StatusCode::NOT_ACCEPTABLE;
            Ok(resp)
        }
    }
}

pub async fn http_request<T, BS, AS>(
    req: Request<IncomingBody>,
    stream: T,
    before: Option<BS>,
    after: Option<AS>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    BS: Service<Request<IncomingBody>, Future = RequestFuture>,
    AS: Service<Response<BoxBody<Bytes, hyper::Error>>, Future = ResponseFuture>,
{
    debug!("connect success");

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    let req = if let Some(before) = before {
        before.call(req).await.unwrap()
    } else {
        req
    };
    let resp = sender.send_request(req).await?;
    let resp = resp.map(|b| b.boxed());
    let resp = if let Some(after) = after {
        after.call(resp).await.unwrap()
    } else {
        resp
    };
    Ok(resp)
}

pub struct PrintReq;

impl Service<Request<IncomingBody>> for PrintReq {
    type Response = Request<IncomingBody>;
    type Error = ();
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        Box::pin(async move {
            info!("{:?}", req);
            Ok(req)
        })
    }
}

pub struct PrintResp;

impl Service<Response<BoxBody<Bytes, hyper::Error>>> for PrintResp {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = ();
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, resp: Response<BoxBody<Bytes, hyper::Error>>) -> Self::Future {
        Box::pin(async move {
            info!("{:?}", resp);
            Ok(resp)
        })
    }
}
