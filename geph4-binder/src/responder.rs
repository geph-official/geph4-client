use std::time::Duration;

use crate::bindercore::BinderCore;
use binder_transport::{BinderError, BinderRequestData, BinderResponse, BinderServer};

/// Retry an action indefinitely when the database errors out
fn db_retry<T>(action: impl Fn() -> Result<T, BinderError>) -> Result<T, BinderError> {
    loop {
        match action() {
            Err(BinderError::DatabaseFailed) => {
                std::thread::sleep(Duration::from_secs(1));
            }
            x => break x,
        }
    }
}

/// Respond to requests coming from the given BinderServer, using the given BinderCore.
pub fn handle_requests(serv: impl BinderServer, core: &BinderCore) -> anyhow::Result<()> {
    loop {
        let req = serv.next_request()?;
        match &req.request_data {
            // password change request
            BinderRequestData::ChangePassword {
                username,
                old_password,
                new_password,
            } => {
                log::debug!("request")
                let res =
                    db_retry(|| core.change_password(&username, &old_password, &new_password))
                        .map(|_| BinderResponse::Okay);
                req.respond(res)
            }
            _ => unimplemented!(),
        }
    }
}
