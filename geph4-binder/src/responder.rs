use std::time::{Duration, Instant};

use crate::bindercore::BinderCore;
use binder_transport::{BinderError, BinderRequestData, BinderResponse, BinderServer};
/// Retry an action indefinitely when the database errors out
fn db_retry<T>(action: impl Fn() -> Result<T, BinderError>) -> Result<T, BinderError> {
    for retries in 1.. {
        match action() {
            Err(BinderError::DatabaseFailed) => {
                if retries > 10 {
                    return Err(BinderError::DatabaseFailed);
                }
                std::thread::sleep(Duration::from_millis(rand::random::<u64>() % 100));
            }
            x => return x,
        }
    }
    unreachable!()
}

/// Respond to requests coming from the given BinderServer, using the given BinderCore.
pub fn handle_requests(serv: impl BinderServer, core: &BinderCore) {
    easy_parallel::Parallel::new()
        .each(0..64, |worker_id| loop {
            if let Err(e) = { handle_request_once(&serv, core) } {
                log::warn!("worker {} restarting ({})", worker_id, e)
            }
        })
        .run();
}

fn handle_request_once(serv: &impl BinderServer, core: &BinderCore) -> anyhow::Result<()> {
    let req = serv.next_request()?;
    let start = Instant::now();
    let res = match &req.request_data {
        // password change request
        BinderRequestData::ChangePassword {
            username,
            old_password,
            new_password,
        } => db_retry(|| core.change_password(&username, &old_password, &new_password))
            .map(|_| BinderResponse::Okay),
        // get epoch key
        BinderRequestData::GetEpochKey { epoch, level } => db_retry(|| {
            let subkey = core.get_epoch_key(level, *epoch as usize)?;
            Ok(BinderResponse::GetEpochKeyResp(subkey))
        }),
        // authenticate
        BinderRequestData::Authenticate {
            username,
            password,
            level,
            epoch,
            blinded_digest,
        } => db_retry(|| {
            let (user_info, blind_signature) = core.authenticate(
                &username,
                &password,
                level,
                *epoch as usize,
                &blinded_digest,
            )?;
            Ok(BinderResponse::AuthenticateResp {
                user_info,
                blind_signature,
            })
        }),
        // validate a blinded digest
        BinderRequestData::Validate {
            level,
            unblinded_digest,
            unblinded_signature,
        } => db_retry(|| core.validate(level, unblinded_digest, unblinded_signature))
            .map(BinderResponse::ValidateResp),
        // get a CAPTCHA
        BinderRequestData::GetCaptcha => db_retry(|| {
            let (captcha_id, png_data) = core.get_captcha()?;
            Ok(BinderResponse::GetCaptchaResp {
                captcha_id,
                png_data,
            })
        }),
        // register a user
        BinderRequestData::RegisterUser {
            username,
            password,
            captcha_id,
            captcha_soln,
        } => db_retry(|| {
            core.create_user(username, password, captcha_id, captcha_soln)?;
            Ok(BinderResponse::Okay)
        }),
        // delete a user
        BinderRequestData::DeleteUser { username, password } => db_retry(|| {
            core.delete_user(username, password)?;
            Ok(BinderResponse::Okay)
        }),
        // add bridge route
        BinderRequestData::AddBridgeRoute {
            sosistab_pubkey,
            bridge_address,
            bridge_group,
            exit_hostname,
            route_unixtime,
            exit_signature,
        } => db_retry(|| {
            core.add_bridge_route(
                *sosistab_pubkey,
                *bridge_address,
                bridge_group,
                exit_hostname,
                *route_unixtime,
                *exit_signature,
            )?;
            Ok(BinderResponse::Okay)
        }),
        // get exits
        BinderRequestData::GetExits => db_retry(|| {
            let response = core.get_exits()?;
            Ok(BinderResponse::GetExitsResp(response))
        }),
        // get bridges
        BinderRequestData::GetBridges {
            level,
            unblinded_digest,
            unblinded_signature,
            exit_hostname,
        } => db_retry(|| {
            let resp =
                core.get_bridges(level, unblinded_digest, unblinded_signature, exit_hostname)?;
            Ok(BinderResponse::GetBridgesResp(resp))
        }),
    };
    log::debug!("response in {} ms", start.elapsed().as_millis());
    req.respond(res);
    Ok(())
}
