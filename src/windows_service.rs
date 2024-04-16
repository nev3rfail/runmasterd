use std::{env, ptr, thread};
use execute::Execute;
use futures::{SinkExt, StreamExt};
use std::ffi::{c_void, OsString};
use std::fs::OpenOptions;
use std::future::Future;
use std::ops::{ControlFlow, Deref};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::IntoRawHandle;
use std::os::windows::prelude::OsStrExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::str::EncodeUtf16;
use std::sync::mpsc::{Sender, SyncSender};
use std::thread::sleep;
use std::time::Duration;
use anyhow::Context;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processenv::SetStdHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winbase::{FormatMessageW, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY, WCHAR, LPWSTR};
use windows_service::service::{ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::{
    define_windows_service, service_control_handler, service_dispatcher,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use anyhow::Result;
use futures::channel::mpsc::Receiver;
use tokio::runtime::Handle;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::shellapi::{ShellExecuteExW, SHELLEXECUTEINFOW};
use crate::start;

pub const SERVICE_NAME: &str = env!("CARGO_PKG_NAME");
pub const SERVICE_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

pub fn service_routine(name: &str, description: &str) {
    if std::env::args().any(|item|&item == "service") {
        start_service().expect("Service failed");
    } else {
        create().expect("TODO: panic message");
    }
}


pub(crate) fn start_service() -> Result<()> {
    define_windows_service!(ffi_service_main, init_windows_service);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("service_dispatcher::start").inspect_err(|e| {
        println!("{:?}", get_last_error_message());
    }).expect("Service start failed.");


    Ok(())
}

fn set_status(status_handle: ServiceStatusHandle, new_state: ServiceState, exit_code: Option<u32>) {
    exit_code.unwrap_or(1);
    let next_status = ServiceStatus {
        // Should match the one from system service registry
        service_type: ServiceType::OWN_PROCESS,
        // The new state
        current_state: new_state, //ServiceState::Running,
        // Accept stop events when running
        controls_accepted: ServiceControlAccept::STOP,
        // Used to report an error when starting or stopping only, otherwise must be zero
        exit_code: ServiceExitCode::ServiceSpecific(exit_code.unwrap_or(0)),
        // Only used for pending states, otherwise must be zero
        checkpoint: 0,
        // Only used for pending states, otherwise must be zero
        wait_hint: Duration::default(),
        // Unused for setting status
        process_id: None,
    };
    log::trace!("Trying to set \"{:?}\" status.", new_state);
    match status_handle.set_service_status(next_status) {
        Ok(res) => {
            log::trace!("Status \"{:?}\" set.", new_state);
            res
        }
        Err(err) => {
            log::error!("Failed to set service status: {:?}", err);
            panic!("Failed to set service status");
        }
    };
}

async fn run_service_or_die_with_honor() -> u32 {
    match start().await {
        Ok(_res) => {
            log::trace!("service service thread finished successfully.");
            0
        }
        Err(err) => {
            log::error!("service service thread exited with error: {:?}", err);
            1024
        }
    }
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}


use std::sync::mpsc::channel as sync_channel;
use futures::channel::mpsc::channel as async_channel;
use winapi::shared::minwindef::TRUE;
use crate::util::{elevate_self, is_elevated, Terminate, Widen};

pub(crate) async fn run_service(_arguments: Vec<OsString>) -> Result<()> {
    log::trace!("Registering service control handler");

    // Synchronous channel for communication between the sync and async parts
    let (sync_sender, sync_receiver) = sync_channel::<u32>();

    // Async channel for the main async runtime to listen on
    let (async_sender, mut async_receiver) = async_channel::<u32>(8);

    // Register the service control handler with a closure that sends messages through the sync channel
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
        match control_event {
            ServiceControl::Stop => {
                log::trace!("Service stop requested.");
                // Send the stop signal to the sync channel
                sync_sender.send(0).unwrap_or_else(|e| log::error!("Failed to send stop signal: {}", e));
                log::trace!("sync stop sent.");
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => {
                log::trace!("Service interrogated.");
                ServiceControlHandlerResult::NoError
            }
            _ => {
                log::trace!("Received an unhandled control event: {:?}", control_event);
                ServiceControlHandlerResult::NotImplemented
            }
        }
    }).expect("Failed to register service control handler");

    set_status(status_handle, ServiceState::Running, None);
    log::trace!("Starting service.");

    // Spawn a thread to bridge the sync and async channels
    thread::spawn(move || {
        while let Ok(code) = sync_receiver.recv() {
            println!("Got code into receiver: {}", code);
            let mut sender = async_sender.clone();
            //let _ = Handle::current().enter();
            tokio::runtime::Builder::new_current_thread()
                .thread_name("glue-thread")
                .enable_all()
                .build().expect("Can't start runtime to stop the service")
                .block_on(async {
                    println!("Created new runtime, running tokio: {}", code);
                    sender.send(code).await.unwrap_or_else(|e| log::error!("Failed to forward stop signal to async channel: {}", e));
                });
        }
    });


    log::trace!("Selecting.");
    tokio::select! {
        res = async_receiver.next() => {
            log::trace!("service_shutdown_channel_received with code {:?}", res);
            set_status(status_handle, ServiceState::Stopped, res);
        }
        res = run_service_or_die_with_honor() => {
            log::trace!("service_shutdown_channel_received with code {:?}", res);
            set_status(status_handle, ServiceState::Stopped, Some(res));
        }
    }
    ;
    log::trace!("Got to the end of service body.");
    Ok(())
}

pub fn set_std_handle() {
    log::trace!("Trying to bind stdout and stderr to files.");
    let dir = env::current_exe().expect("Can't get current exe");
    let _ = std::fs::create_dir_all(&dir).is_ok();

    let stderr = OpenOptions::new().write(true).create(true).truncate(true).open(dir.with_file_name("stderr.log"))
        .expect("failed to create stderr.log")
        .into_raw_handle();
    let stdout = OpenOptions::new().write(true).create(true).truncate(true).open(dir.with_file_name("stdout.log"))
        .expect("failed to create stdout.log")
        .into_raw_handle();
    unsafe {
        let re = SetStdHandle(STD_ERROR_HANDLE, stderr);
        let ro = SetStdHandle(STD_OUTPUT_HANDLE, stdout);
        log::trace!("Bind stderr to file result: {:?}", re);
        log::trace!("Bind stdout to file result: {:?}", ro);
    };
}

fn init_windows_service(arguments: Vec<OsString>) {
    set_std_handle();
    log::trace!("Trying to run windows service");
    tokio::runtime::Builder::new_current_thread()
        .thread_name("service-tread")
        .enable_all()
        .build().expect("Can't start runtime to stop the service")
        .block_on(async {
            match run_service(arguments).await {
                Ok(res) => {
                    log::trace!("Windows service run ended.");
                    res
                }
                Err(err) => {
                    log::error!("Windows service failed to start: {:?}", err);
                    panic!("Windows service failed to start");
                }
            }
        })
}


pub fn create() -> Result<()> {
    
    if let ControlFlow::Break(e) = elevate_self() {
        return e;
    }
    

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;

    let my_service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DESCRIPTION),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().context("Get current exe for ServiceInfo")?,
        launch_arguments: vec!["--service".parse()?],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let existing_service = manager.open_service(SERVICE_NAME, service_access);
    match existing_service {
        Ok(exists) => {
            println!("Service exists, changing path");
            exists.change_config(&my_service_info)?;
        }
        Err(_) => {
            println!("Not exists, creating...");
            manager.create_service(&my_service_info, ServiceAccess::QUERY_STATUS)?;
        }
    }
    //println!("{:?}", existing_service.query_status());

    let the_service = manager.open_service(SERVICE_NAME, service_access)?;
    println!("{:?}", &the_service.query_status());
    the_service.start(&[""]).expect("TODO: panic message");
    println!("{:?}", &the_service.query_status());
    Ok(())
}

pub fn get_last_error_message() -> String {
    unsafe {
        let error_code = GetLastError();

        let mut buffer: LPWSTR = null_mut();
        let buffer_size = FormatMessageW(
            winapi::um::winbase::FORMAT_MESSAGE_ALLOCATE_BUFFER
                | winapi::um::winbase::FORMAT_MESSAGE_FROM_SYSTEM
                | winapi::um::winbase::FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null_mut(),
            error_code,
            winapi::um::winnt::MAKELANGID(
                winapi::um::winnt::LANG_NEUTRAL,
                winapi::um::winnt::SUBLANG_DEFAULT,
            ) as u32,
            (&mut buffer as *mut _ as LPWSTR) as LPWSTR,
            0,
            null_mut(),
        );

        let message = if buffer_size > 0 {
            let message =
                OsString::from_wide(std::slice::from_raw_parts(buffer, buffer_size as usize));
            winapi::um::winbase::LocalFree(buffer as *mut winapi::ctypes::c_void);
            message.to_string_lossy().into_owned()
        } else {
            "Failed to retrieve error message.".to_owned()
        };
        format!("[{}]: {}", error_code, message)
    }
}