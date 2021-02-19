use std::time::Duration;

use crate::bindercore::BinderCore;
use binder_transport::{BinderError, BinderRequestData, BinderResponse, BinderServer};
use rand::prelude::*;
/// Retry an action indefinitely when the database errors out
fn db_retry<T>(action: impl Fn() -> Result<T, BinderError>) -> Result<T, BinderError> {
    for retries in 1.. {
        match action() {
            Err(BinderError::DatabaseFailed(s)) => {
                if retries > 5 {
                    log::warn!("DB retried many times now: {}", s);
                    return Err(BinderError::DatabaseFailed(s));
                }
                let sleep_low = 2u64.pow(retries) * 50;
                let sleep_high = 2u64.pow(retries + 1) * 50;
                let actual = rand::thread_rng().gen_range(sleep_low, sleep_high);
                log::warn!(
                    "[retries={}] DB contention ({}); sleeping for {} ms",
                    retries,
                    s,
                    actual
                );
                std::thread::sleep(Duration::from_millis(actual));
            }
            x => return x,
        }
    }
    unreachable!()
}

/// Respond to requests coming from the given BinderServer, using the given BinderCore.
pub fn handle_requests(serv: impl BinderServer, core: &BinderCore, statsd_client: statsd::Client) {
    easy_parallel::Parallel::new()
        .each(0..8, |worker_id| loop {
            if let Err(e) = { handle_request_once(&serv, core, &statsd_client) } {
                log::warn!("worker {} restarting ({})", worker_id, e)
            }
        })
        .run();
}

fn handle_request_once(
    serv: &impl BinderServer,
    core: &BinderCore,
    statsd_client: &statsd::Client,
) -> anyhow::Result<()> {
    let req = serv.next_request()?;
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
            statsd_client.incr("GetEpochKey");
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
            statsd_client.incr("Authenticate");
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
        } => db_retry(|| {
            statsd_client.incr("Validate");
            core.validate(level, unblinded_digest, unblinded_signature)
        })
        .map(BinderResponse::ValidateResp),
        // get a CAPTCHA
        BinderRequestData::GetCaptcha => db_retry(|| {
            let (captcha_id, png_data) = core.get_captcha()?;
            statsd_client.incr("GetCaptcha");
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
            statsd_client.incr("RegisterUser");
            Ok(BinderResponse::Okay)
        }),
        // delete a user
        BinderRequestData::DeleteUser { username, password } => db_retry(|| {
            core.delete_user(username, password)?;
            statsd_client.incr("DeleteUser");
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
            statsd_client.incr("AddBridgeRoute");
            Ok(BinderResponse::Okay)
        }),
        // get exits
        BinderRequestData::GetExits => db_retry(|| {
            let response = core.get_exits(false)?;
            statsd_client.incr("GetExits");
            Ok(BinderResponse::GetExitsResp(response))
        }),
        BinderRequestData::GetFreeExits => db_retry(|| {
            let response = core.get_exits(true)?;
            statsd_client.incr("GetFreeExits");
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
            statsd_client.incr("GetBridges");
            Ok(BinderResponse::GetBridgesResp(resp))
        }),
    };
    req.respond(res);
    Ok(())
}
