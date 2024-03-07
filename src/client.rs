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

use crate::state::ClientState;
use crate::util::{self, create_ssl_connection};

#[derive(Clone)]
pub struct HttpClient;

#[service]
impl Service<ClientState, Request<IncomingBody>> for HttpClient {
    async fn call(
        &self,
        state: &mut ClientState,
        req: Request<IncomingBody>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if state.is_secure {
            if let Ok(stream) = create_ssl_connection(&state.addr, &state.sni)
                .await
                .inspect_err(|e| error!("create ssl stream failed: {e}"))
            {
                return http_request(req, stream).await;
            }
        } else if let Ok(stream) = TcpStream::connect(&state.addr)
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
