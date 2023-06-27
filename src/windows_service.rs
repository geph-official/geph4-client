use std::ffi::OsString;

use windows_service::{
    service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::config::AuthOpt;

const SERVICE_NAME: &str = "GephDaemon";

pub fn extract_connect_args(auth: &AuthOpt) -> Vec<&str> {
    match &auth.auth_kind {
        crate::config::AuthKind::AuthPassword { username, password } => {
            let mut args = Vec::new();
            args.push("auth-password");
            args.push("--username");
            args.push(&username);
            args.push("--password");
            args.push(&password);
            args
        }
        _ => unimplemented!(),
    }
}

pub fn install_windows_service() -> anyhow::Result<()> {
    log::info!("Installing Geph Daemon as a Windows service");

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let mut service_binary_path = dirs::home_dir().unwrap();
    service_binary_path.push(".cargo");
    service_binary_path.push("bin");
    service_binary_path.push("geph_daemon.exe");
    log::info!("windows service binary path: {:?}", service_binary_path);

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

pub fn start_service(args: Vec<&str>) -> anyhow::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::START)?;

    log::info!("Starting Geph Daemon Windows service...");
    service.start(args.as_slice())?;
    log::info!("Successfully started Geph Daemon Windows service!");
    Ok(())
}

pub fn stop_service() -> anyhow::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    )?;
    let service_status = service.query_status()?;

    if service_status.current_state != ServiceState::StopPending
        && service_status.current_state != ServiceState::Stopped
    {
        log::info!("Stopping Geph Daemon Windows service...");
        service.stop()?;
        log::info!("Successfully stopped Geph Daemon Windows service!");
    }

    Ok(())
}
