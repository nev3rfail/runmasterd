//#![windows_subsystem = "windows"]
use std::time::Duration;
use tracing_subscriber::fmt::format::FmtSpan;
use crate::configurator::configurator;
use crate::windows_service::{create, set_std_handle};
mod windows_service;
mod r#static;
mod configurator;
mod util;
mod startup;


#[tokio::main]
async fn main() {
    
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        //.event_format(Format::default().with_timer(fmt::time::uptime()))
        .with_span_events(FmtSpan::ENTER| FmtSpan::CLOSE)
        .with_thread_names(true)
        //.event_format(MyFormatter)
        .init();
    let mut is_interactive = false;
    let mut is_service = false;
    let mut is_configurator = false;

    for item in std::env::args() {
        match item.as_str() {
            "--interactive" => is_interactive = true,
            "--service" => is_service = true,
            "--configurator" => is_configurator = true,
            _ => {}
        }
    }
    let is_installer = !is_interactive && !is_service && !is_configurator;
    if is_service {
        set_std_handle();
        windows_service::start_service().expect("Service failed");
    } else if is_interactive {
        start().await.expect("Interactive run failed")
    } else if is_installer {
        create().expect("Installer failed");
    } else if is_configurator {
        configurator().expect("Configurator failed.")
    } else {
        panic!("Don't know what to do. arguments: {:?}", std::env::args());
    }
    //sleep(Duration::from_secs(20));
    //
}

pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("Yo");
    std::thread::sleep(Duration::from_secs(100));
    Ok(())
}

