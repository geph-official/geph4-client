use std::{ops::Deref, sync::Arc, time::Duration};

use crate::{
    config::{get_conninfo_store, Opt, CONFIG},
    conninfo_store::ConnInfoStore,
};

static CONNINFO_STORE: async_once_cell::OnceCell<Arc<ConnInfoStore>> =
    async_once_cell::OnceCell::new();

pub async fn global_conninfo_store() -> Arc<ConnInfoStore> {
    CONNINFO_STORE
        .get_or_init(async {
            let (common, auth, exit_host) = match CONFIG.deref() {
                Opt::Connect(c) => (
                    &c.common,
                    &c.auth,
                    c.exit_server.clone().unwrap_or_default(),
                ),
                _ => panic!(),
            };

            loop {
                match get_conninfo_store(common, auth, &exit_host).await {
                    Ok(store) => {
                        log::info!(
                            "successfully created conninfo store with user_info: {:?}",
                            store.user_info()
                        );
                        return Arc::new(store);
                    }
                    Err(err) => log::warn!("could not get conninfo store: {:?}", err),
                }
                smol::Timer::after(Duration::from_secs(1)).await;
            }
        })
        .await
        .clone()
}

// /// The configured binder client
// static CONNINFO_STORE: Lazy<Arc<ConnInfoStore>> = Lazy::new(|| {
//     Arc::new({
//         let (common, auth, exit_host) = match CONFIG.deref() {
//             Opt::Connect(c) => (
//                 &c.common,
//                 &c.auth,
//                 c.exit_server.clone().unwrap_or_default(),
//             ),
//             _ => panic!(),
//         };
//         log::debug!("about to construct the global conninfo");
//         smol::future::block_on(async move {
//             loop {
//                 log::debug!("inside the blocked-on future for conninfo");
//                 match get_conninfo_store(common, auth, &exit_host).await {
//                     Ok(store) => {
//                         log::info!(
//                             "successfully created conninfo store with user_info: {:?}",
//                             store.user_info()
//                         );
//                         return store;
//                     }
//                     Err(err) => log::warn!("could not get conninfo store: {:?}", err),
//                 }
//                 smol::Timer::after(Duration::from_secs(1)).await;
//             }
//         })
//     })
// });
