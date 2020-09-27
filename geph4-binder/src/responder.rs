use crate::bindercore::BinderCore;
use binder_transport::{BinderRequestData, BinderServer};

/// Respond to requests coming from the given BinderServer, using the given BinderCore.
pub fn handle_requests(serv: impl BinderServer, core: &BinderCore) -> anyhow::Result<()> {
    loop {
        let req = serv.next_request()?;
        match req.request_data {
            BinderRequestData::Authenticate {
                username,
                password,
                blinded_digest,
            } => unimplemented!(),
            BinderRequestData::Dummy => unimplemented!(),
        }
    }
}
