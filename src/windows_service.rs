use std::ffi::OsString;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::config::ConnectOpt;

const SERVICE_NAME: &str = "GephDaemon";

pub fn install_windows_service() -> anyhow::Result<()> {
    log::info!("Installing Geph Daemon as a Windows service");

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    // This example installs the service defined in `examples/ping_service.rs`.
    // In the real world code you would set the executable path to point to your own binary
    // that implements windows service.
    let service_binary_path = ::std::env::current_exe()
        .unwrap()
        .with_file_name("geph4-client.exe");

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Geph Daemon"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };
    let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description("Geph Daemon Windows Service (geph4-client)")?;

    log::info!("Successfully installed Geph Daemon as a Windows service");

    Ok(())
}

pub fn start_service(opt: &ConnectOpt) -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    let args = extract_connect_args(opt);

    log::info!(
        "Attemping to start GephDaemon service with {SERVICE_NAME} with args: {:?}",
        args
    );

    service.start(args.as_slice())?;
    log::info!("Successfully started GephDaemon service");
    Ok(())
}

fn extract_connect_args(opt: &ConnectOpt) -> Vec<&str> {
    match &opt.auth.auth_kind {
        crate::config::AuthKind::AuthPassword { username, password } => {
            let mut args = Vec::new();
            args.push("auth-password");
            args.push("--username");
            args.push(username);
            args.push("--password");
            args.push(password);
            args
        }
        _ => unimplemented!(),
    }
}

pub fn is_service_running() -> anyhow::Result<bool> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;

    let service_status = service.query_status()?;
    Ok(service_status.current_state == ServiceState::Running)
}

define_windows_service!(ffi_service_main, daemon_service_main);

fn daemon_service_main(args: Vec<OsString>) {}
