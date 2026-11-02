//! What a binary adds to the proxy this workspace assembles.
//!
//! There are exactly three things a binary can add that cannot be expressed as policy or
//! configuration: authenticators for kinds of credential this workspace does not read, layers that
//! sit between authorization and the enforcement stack, and management routes. Everything else
//! about the stack is fixed, so the order of the security-relevant layers is reviewable in one file.

use crate::startup::RequestPath;
use axum::{Router, extract::Request, response::Response};
use libra_identity_authenticator::authenticator::Authenticator;
use libra_management_auth::PrivilegeSettings;
use std::{convert::Infallible, sync::Arc};
use tower::{
    Layer,
    util::{BoxCloneSyncService, BoxCloneSyncServiceLayer},
};

/// The half of the stack that reads the authorization decision.
pub type Enforcement = BoxCloneSyncService<Request, Response, Infallible>;

/// A layer placed around the enforcement stack, below authorization.
pub type OuterLayer = BoxCloneSyncServiceLayer<Enforcement, Request, Response, Infallible>;

/// Management routes a binary adds, built once the request path exists and mounted behind a privilege
/// gate.
pub struct GatedRoutes {
    /// Who may call these routes.
    pub privilege: PrivilegeSettings,
    /// Builds the routes from what the proxy judges requests with.
    pub routes: Box<dyn FnOnce(&RequestPath) -> Router + Send>,
}

/// Everything a binary adds. [`Default`] adds nothing, as the binary in this repository does.
#[derive(Default)]
pub struct Extensions {
    /// Authenticators after the ones every build runs. Each must recognize credentials no other
    /// authenticator does: a credential two recognize is refused.
    pub authenticators: Vec<Arc<dyn Authenticator>>,
    /// Layers around the enforcement stack, outermost first. They are below authorization, so a
    /// request that reaches one has been authenticated and has a decision.
    pub layers: Vec<OuterLayer>,
    /// Extra management routes.
    pub management_routes: Vec<GatedRoutes>,
}

/// Wraps `core` in `outer`, first layer outermost.
///
/// Folded innermost-first so that the order a binary lists its layers in is the order a request
/// meets them in.
#[must_use]
pub fn wrap(core: Enforcement, outer: Vec<OuterLayer>) -> Enforcement {
    outer.into_iter().rev().fold(core, |inner, layer| layer.layer(inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::{
        mem::take,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };
    use tower::{Service, ServiceExt, service_fn};

    type Trace = Arc<Mutex<Vec<&'static str>>>;

    /// A layer that records its name when a request passes through it, then calls on.
    #[derive(Clone)]
    struct Recorder {
        name: &'static str,
        trace: Trace,
    }

    #[derive(Clone)]
    struct RecorderService<S> {
        name: &'static str,
        trace: Trace,
        inner: S,
    }

    impl<S> Layer<S> for Recorder {
        type Service = RecorderService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            RecorderService {
                name: self.name,
                trace: Arc::clone(&self.trace),
                inner,
            }
        }
    }

    impl<S> Service<Request> for RecorderService<S>
    where
        S: Service<Request, Response = Response, Error = Infallible>,
    {
        type Response = Response;
        type Error = Infallible;
        type Future = S::Future;

        fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(context)
        }

        fn call(&mut self, request: Request) -> Self::Future {
            self.trace.lock().unwrap().push(self.name);
            self.inner.call(request)
        }
    }

    fn core(trace: &Trace) -> Enforcement {
        let trace = Arc::clone(trace);
        BoxCloneSyncService::new(service_fn(move |_request: Request| {
            let trace = Arc::clone(&trace);
            async move {
                trace.lock().unwrap().push("core");
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        }))
    }

    fn layer(name: &'static str, trace: &Trace) -> OuterLayer {
        BoxCloneSyncServiceLayer::new(Recorder {
            name,
            trace: Arc::clone(trace),
        })
    }

    async fn visited(outer: impl FnOnce(&Trace) -> Vec<OuterLayer>) -> Vec<&'static str> {
        let trace = Trace::default();
        let mut service = wrap(core(&trace), outer(&trace));
        service.ready().await.unwrap().call(Request::new(Body::empty())).await.unwrap();
        take(&mut *trace.lock().unwrap())
    }

    #[tokio::test]
    async fn no_extra_layers_leaves_only_the_core() {
        assert_eq!(visited(|_| Vec::new()).await, ["core"]);
    }

    #[tokio::test]
    async fn the_first_extra_layer_is_met_first_and_the_core_last() {
        let order = visited(|trace| vec![layer("cache", trace), layer("dedup", trace), layer("aggregation", trace)]).await;

        assert_eq!(order, ["cache", "dedup", "aggregation", "core"]);
    }

    #[test]
    fn a_default_extensions_adds_nothing() {
        let extensions = Extensions::default();

        assert!(extensions.authenticators.is_empty());
        assert!(extensions.layers.is_empty());
        assert!(extensions.management_routes.is_empty());
    }
}
