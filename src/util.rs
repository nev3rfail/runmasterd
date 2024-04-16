use std::env::current_exe;
use std::ffi::c_void;
use std::ops::ControlFlow;
use std::ops::ControlFlow::{Break, Continue};
use std::{ptr, thread};
use std::ptr::null_mut;
use std::str::EncodeUtf16;
use std::time::Duration;
use winapi::shared::minwindef::TRUE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::shellapi::{ShellExecuteExW, SHELLEXECUTEINFOW};
use winapi::um::winnt::{HANDLE, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, WCHAR};
use crate::windows_service::get_last_error_message;
use anyhow::{Context, Error, Result};

pub(crate) fn is_elevated() -> bool {
    let mut result = false;
    unsafe {
        let mut handle: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) != 0 {
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };

            let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let mut ret_size = size;
            if GetTokenInformation(
                handle,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
                size as _,
                &mut ret_size,
            ) != 0
            {
                result = elevation.TokenIsElevated == 1;
            }
        }
        if !handle.is_null() {
            CloseHandle(handle);
        }
    }
    result
}



pub(crate) trait Terminate {
    fn terminate(&self) -> Vec<WCHAR>;
}

impl<'a> Terminate for EncodeUtf16<'a> {
    fn terminate(&self) -> Vec<WCHAR> {
        self.clone().chain(std::iter::once(0)).collect()
    }
}

pub(crate) trait Widen {
    fn widen(&self) -> EncodeUtf16;
}

impl Widen for String {
    fn widen(&self) -> EncodeUtf16 {
        self.encode_utf16()
    }
}

impl Widen for &str {
    fn widen(&self) -> EncodeUtf16 {
        self.encode_utf16()
    }
}

pub(crate) fn elevate_self() -> ControlFlow<Result<()>, ()> {
    if is_elevated() {
        Continue(())
    } else {
        // elevate and circuit break
        Break(get_self().and_then(|r|elevate(r[0].as_str(), r[1].as_str())))
    }
}

pub(crate) fn elevate(program: &str, args: &str) -> Result<()> {
    println!("Elevating application `{}` with arguments `{}`", program, args);
    let mut sei = SHELLEXECUTEINFOW {
        //fMask: SEE_MASK_NO_CONSOLE,
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        lpVerb: "runas".widen().terminate().as_ptr(),
        lpFile: program.widen().terminate().as_ptr(),
        lpParameters: args.widen().terminate().as_ptr(),
        hwnd: ptr::null_mut(),
        nShow: 1, // # SW_NORMAL,
        ..unsafe { std::mem::zeroed() }
    };

    unsafe {
        if ShellExecuteExW(&mut sei) == TRUE {
            println!("elevated");
            Ok(())
        } else {
            println!("Error executing elevated app: {:?}", get_last_error_message());
            Err(anyhow::Error::msg(get_last_error_message()))
        }
    }
}

/// Returns current executable path and the glued command line arguments.
fn get_self() -> Result<[String; 2]> {
    let absolute_exe = process_path::get_executable_path()
        .ok_or(anyhow::Error::msg("Can't executable path"))?
        .to_string_lossy().into_owned();
    let args: Vec<String> = std::env::args().collect();
    println!("({}) // {:?}", absolute_exe, args);
    let filtered_args = if absolute_exe.ends_with(args.first().ok_or(anyhow::Error::msg("Can't read arg"))?) {
        &args[1..]  // Skip the first element if it's the executable path
    } else {
        &args[..]   // Include all arguments otherwise
    }.join(" ");
    
    println!("f: {}", filtered_args);
    Ok([absolute_exe, filtered_args])
}
