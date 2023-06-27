use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command},
    sync::{mpsc, Arc},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

fn main() {
    run();
}

const SERVICE_NAME: &str = "GephDaemon";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, daemon_service_main);

pub fn run() {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .expect("Failed to start Windows service for GephDaemon");
}

fn daemon_service_main(args: Vec<OsString>) {
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
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .expect("could not register event handler for daemon");

    // Tell the system that service is running
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("could not update daemon status to running");

    // main logic here!! spawn the daemon
    Command::new("geph4-client")
        .arg("connect")
        .args(args)
        .spawn()
        .expect("big F lul");

    // Tell the system that service has stopped.
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("could not update daemon status to stopped");
}
