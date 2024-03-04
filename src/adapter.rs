use std::{future::Future, marker::PhantomData, pin::Pin};

use motore::Service;

impl<T: ?Sized, Cx, MotoreReq, HyperReq> HyperAdapter<Cx, MotoreReq, HyperReq> for T where
    T: Service<Cx, MotoreReq>
{
}

pub trait HyperAdapter<Cx, MotoreReq, HyperReq>: Service<Cx, MotoreReq> {
    fn hyper<F>(self, f: F) -> Hyper<Self, F, Cx, MotoreReq>
    where
        F: FnOnce(HyperReq) -> (Cx, MotoreReq),
        Self: Sized,
    {
        Hyper::new(self, f)
    }
}

pub struct Hyper<S, F, Cx, MotoreReq> {
    inner: S,
    f: F,
    _phantom: PhantomData<fn(Cx, MotoreReq)>,
}

impl<S, F, Cx, MotoreReq> Hyper<S, F, Cx, MotoreReq> {
    pub fn new(inner: S, f: F) -> Self {
        Self {
            inner,
            f,
            _phantom: PhantomData,
        }
    }
}

impl<S, F, Cx, MotoreReq, HyperReq> hyper::service::Service<HyperReq> for Hyper<S, F, Cx, MotoreReq>
where
    S: Service<Cx, MotoreReq> + Clone + 'static + Send,
    F: FnOnce(HyperReq) -> (Cx, MotoreReq) + Clone,
    MotoreReq: 'static + Send,
    Cx: 'static + Send,
{
    type Response = S::Response;

    type Error = S::Error;

    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static + Send>>;

    fn call(&self, req: HyperReq) -> Self::Future {
        let inner = self.inner.clone();
        let (mut cx, r) = (self.f.clone())(req);
        Box::pin(async move { inner.call(&mut cx, r).await })
    }
}
