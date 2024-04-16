
use winapi::um::combaseapi::{CoCreateInstance, CoTaskMemFree};
use winapi::um::shlobj::SHGetKnownFolderPath;
use winapi::shared::winerror::SUCCEEDED;
use winapi::um::knownfolders::FOLDERID_Startup;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use winapi::um::shobjidl_core::IShellLinkW;
use winapi::um::shobjidl_core::ShellLink;
use winapi::{Class, Interface};
use winapi::um::objidl::IPersistFile;
use winapi::um::winnt::{LPCWSTR, WCHAR};
use winapi::um::propkey::PKEY_Link_Arguments;
use std::ptr::null_mut;
use winapi::um::coml2api::STGM_READ;
use winapi::shared::wtypesbase::CLSCTX_INPROC_SERVER;
use crate::util::{Terminate, Widen};
use anyhow::{Error, Result};
use winapi::um::propidl::PROPVARIANT;


pub (crate) fn get_startup_folder_path() -> Option<OsString> {
    unsafe {
        let mut path_ptr = null_mut();
        if SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_Startup, 0, null_mut(), &mut path_ptr)) {
            let len = (0..).take_while(|&i| *path_ptr.offset(i) != 0).count();
            let slice = std::slice::from_raw_parts(path_ptr, len);
            let os_string = OsString::from_wide(slice);
            CoTaskMemFree(path_ptr as _);
            Some(os_string)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct StartupEntry {
    path: PathBuf,
    runas_admin: bool,
    valid: bool,
    allowed: bool
}

pub(crate) fn check_entry_for_admin_flag(shortcut_path: PathBuf) -> Result<bool> {
    unsafe {
        let mut shell_link: *mut IShellLinkW = null_mut();
        let hr = CoCreateInstance(&ShellLink::uuidof(), null_mut(), CLSCTX_INPROC_SERVER, &IShellLinkW::uuidof(), &mut shell_link as *mut *mut _ as *mut *mut std::ffi::c_void);
        if hr < 0 {
            return Ok(false);
        }

        let shell_link = &mut *shell_link;
        let mut pf:  *mut IPersistFile = null_mut();
        let persist_file = shell_link.QueryInterface(&IPersistFile::uuidof(), &mut pf as *mut *mut _ as *mut *mut std::ffi::c_void);
        /*if persist_file.is_null() {
            return Ok(false);
        }*/

        let persist_file = &mut *pf;
        let shortcut_wstr: Vec<u16> = shortcut_path.as_os_str().to_string_lossy().to_string().widen().terminate();
        persist_file.Load(shortcut_wstr.as_ptr(), STGM_READ);

        println!("!!! {:?}", shortcut_wstr);
        // let mut prop_variant = PROPVARIANT::default();
        // shell_link.GetProperties(&PKEY_Link_Arguments, &mut prop_variant);
        // let run_as_admin = matches!(prop_variant.vt, VT_LPWSTR if prop_variant.pwszVal.ends_with("-admin"));
        // 
        // CoTaskMemFree(prop_variant.pwszVal as *mut _);

        //Ok(run_as_admin)
        
        Ok(true)
    }
}

pub(crate) fn find_startup_entries() -> Result<Vec<StartupEntry>> {
    let directory = get_startup_folder_path().ok_or(Error::msg("pew"))?;
    let dir_path = Path::new(&directory);
    let mut entries = Vec::new();

    if let Ok(dir_entries) = fs::read_dir(dir_path) {
        for entry in dir_entries.filter_map(Result::ok) {
            
            let path = entry.path();
            let path2 = path.clone();
            let ext = path2.extension();
            entries.push(crate::startup::StartupEntry {
                path,
                runas_admin: false,
                valid: ext.and_then(OsStr::to_str) == Some("lnk"),
                allowed: false,
            });
        }
    }
    Ok(entries)
}

pub(crate) fn list_startup_entries(directory: &OsString) -> Vec<PathBuf> {
    let dir_path = Path::new(directory);
    let mut entries = Vec::new();

    if let Ok(dir_entries) = fs::read_dir(dir_path) {
        for entry in dir_entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().and_then(OsStr::to_str) == Some("lnk") {
                entries.push(path);
            }
        }
    }
    entries
}