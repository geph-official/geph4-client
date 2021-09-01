use futures_util::{future::Shared, FutureExt};
use geph4_binder_transport::BinderClient;
use smol::Task;
use std::sync::Arc;

/// A "lazy" binder client, evaluated in the background.
pub struct LazyBinderClient<T: BinderClient + ?Sized> {
    generate: Shared<Task<Arc<T>>>,
}

impl<T: BinderClient + ?Sized> LazyBinderClient<T> {
    /// Creates a new LazyBinderClient.
    pub fn new(task: Task<Arc<T>>) -> Self {
        Self {
            generate: task.shared(),
        }
    }
}

#[async_trait::async_trait]
impl<T: BinderClient + ?Sized> BinderClient for LazyBinderClient<T> {
    async fn request(
        &self,
        request: geph4_binder_transport::BinderRequestData,
    ) -> geph4_binder_transport::BinderResult<geph4_binder_transport::BinderResponse> {
        let inner = self.generate.clone().await;
        inner.request(request).await
    }
}
