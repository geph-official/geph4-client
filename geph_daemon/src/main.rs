use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        mpsc::{self, TryRecvError},
        Arc, Mutex,
    },
    thread::Builder,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum AuthKind {
    AuthPassword { username: String, password: String },

    AuthKeypair { sk_path: String },
}

/// Configuration for starting the daemon
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DaemonConfig {
    pub username: String,
    pub password: String,
    pub exit_hostname: String,
    pub force_bridges: bool,
    pub vpn_mode: bool,
    pub prc_whitelist: bool,
    pub listen_all: bool,
    pub force_protocol: Option<String>,
}

pub fn run() {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .expect("Failed to start Windows service for GephDaemon");
}

define_windows_service!(ffi_service_main, daemon_service_main);

fn daemon_service_main(args: Vec<OsString>) {
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

    // Report to the SCM that the service is running.
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

    let config_file_path = PathBuf::from("C:/ProgramData/geph4-credentials/config.json");
    let config_json = std::fs::read_to_string(&config_file_path).unwrap();

    // // Deserialize the JSON string into an AuthKind instance
    let args: Vec<String> =
        serde_json::from_str(&config_json).expect("Failed to deserialize config from JSON");

    let mut cmd = Command::new("geph4-client");
    cmd.args(&args);
    cmd.creation_flags(0x08000000);
    let mut child = cmd.spawn().expect("f");

    let _ = child.wait();

    let shared_child = Arc::new(Mutex::new(child));

    let shared_status_child = Arc::clone(&shared_child);
    let status_handle = status_handle.clone();
    std::thread::spawn(move || loop {
        if let Ok(mut child) = shared_status_child.lock() {
            match child.try_wait() {
                Ok(Some(exit_status)) => {
                    if exit_status.success() {
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
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => panic!("Error waiting for child process: {}", e),
            }

            std::thread::sleep(Duration::from_secs(1));
        }
    });

    let shared_signal_child = Arc::clone(&shared_child);
    // spawn another loop to monitor shutdown signals
    std::thread::spawn(move || loop {
        if let Ok(mut child) = shared_signal_child.lock() {
            match shutdown_rx.try_recv() {
                Ok(_) | Err(TryRecvError::Disconnected) => {
                    let _ = child.kill();

                    status_handle
                        .set_service_status(ServiceStatus {
                            service_type: SERVICE_TYPE,
                            current_state: ServiceState::Stopped,
                            controls_accepted: ServiceControlAccept::STOP,
                            exit_code: ServiceExitCode::Win32(0),
                            checkpoint: 0,
                            wait_hint: Duration::default(),
                            process_id: None,
                        })
                        .expect("Failed to set service status");
                    break;
                }
                Err(TryRecvError::Empty) => {}
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    });
}
