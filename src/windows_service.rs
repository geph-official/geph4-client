use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    process::{Child, Command},
    sync::mpsc,
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::config::{AuthKind, AuthOpt, ConnectOpt};

const SERVICE_NAME: &str = "GephDaemon";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

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
        service_type: SERVICE_TYPE,
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
    // let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    // let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    // let args = extract_connect_args(opt);

    // log::info!(
    //     "Attemping to start GephDaemon service with {SERVICE_NAME} with args: {:?}",
    //     args
    // );

    // service.start(args.as_slice())?;
    // log::info!("Successfully started GephDaemon service");
    // Ok(())
    Ok(())
}

fn extract_connect_args(auth: &AuthOpt) -> Vec<&str> {
    match &auth.auth_kind {
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

pub fn run() {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .expect("Failed to start Windows service for {SERVICE_NAME}");
}

fn daemon_service_main(_args: Vec<OsString>) -> anyhow::Result<()> {
    // idea: spawn the daemon as from `Command::new()`?
    // Create a channel to be able to poll a stop event from the service worker loop.
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Define system service event handler that will be receiving service events.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Notifies a service to report its current status information to the service
            // control manager. Always return NoError even if not implemented.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                shutdown_tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }

            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Tell the system that service is running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // main logic here!!
    // TODO: read the connect opt from the connect.json

    let config_file_path = dirs::config_dir()
        .expect("Could not find configuration directory")
        .join("geph4-credentials/connect.json");
    // Read the config file
    let mut file = File::open(&config_file_path).expect("Failed to open config file");
    let mut config_json = String::new();
    file.read_to_string(&mut config_json)
        .expect("Failed to read config file");

    // Deserialize the JSON string into an AuthKind instance
    let auth: AuthOpt =
        serde_json::from_str(&config_json).expect("Failed to deserialize config from JSON");

    let mut child: Child;
    match auth.auth_kind {
        AuthKind::AuthPassword { username, password } => {
            child = Command::new("geph4-client")
                .arg("connect")
                .arg("auth-password")
                .arg("--username")
                .arg(username)
                .arg("--password")
                .arg(password)
                .spawn()
                .expect("Failed to start service");
        }
        AuthKind::AuthKeypair { sk_path } => {
            child = Command::new("geph4-client")
                .arg("connect")
                .arg("auth-keypair")
                .arg("--sk_path")
                .arg(sk_path)
                .spawn()
                .expect("Failed to start service");
        }
    }

    // Wait for the child process to exit
    let _ = child.wait().expect("Failed to wait on child");

    // Tell the system that service has stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
