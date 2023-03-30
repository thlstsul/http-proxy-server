use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::codec::RequestExt;
use hyper::Request;
use pin_project_lite::pin_project;
use std::io::Write;
use tokio::io::{AsyncRead, AsyncWrite};

type InterceptFn = fn(Request<Vec<u8>>) -> Request<Vec<u8>>;

pin_project! {
    pub struct HttpClientStream<S> {
        #[pin]
        inner: S,
        write_buf: Vec<u8>,
        before: Option<InterceptFn>,
    }
}

impl<S> HttpClientStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            write_buf: Vec::new(),
            before: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_intercept(inner: S, intercept: InterceptFn) -> Self {
        Self {
            inner,
            write_buf: Vec::new(),
            before: Some(intercept),
        }
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Gets a pinned mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        self.project().inner
    }
}

impl<S> AsyncRead for HttpClientStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_pin_mut().poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for HttpClientStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let me = self.project();
        if let Some(before) = me.before {
            match me.write_buf.write(buf) {
                Ok(_) => {
                    if let Some(req) = Request::encode(me.write_buf) {
                        let req = (before)(req);
                        if me.inner.poll_write(cx, &req.decode()).is_pending() {
                            return Poll::Pending;
                        }
                    }
                    Poll::Ready(Ok(buf.len()))
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        } else {
            me.inner.poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.get_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.get_pin_mut().poll_shutdown(cx)
    }
}
