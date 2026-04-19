use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use windows_sys::Win32::Foundation::{FALSE, HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS,
};

use crate::OwnedHandle;

/// Traversing process snapshot and find pid for a specified process name.
/// https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
pub fn find_pid_by_name(name: &str) -> Option<u32> {
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = OwnedHandle::new(raw_snapshot)?;

    let mut pe32: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe32.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot.as_raw(), &mut pe32) } == 0 {
        return None;
    }

    loop {
        let len = pe32
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(pe32.szExeFile.len());
        let pname_wide = &pe32.szExeFile[..len];
        let pname_os = OsString::from_wide(pname_wide);
        let pname = pname_os.to_string_lossy();

        if pname.eq_ignore_ascii_case(name) {
            return Some(pe32.th32ProcessID);
        }

        if unsafe { Process32NextW(snapshot.as_raw(), &mut pe32) } == 0 {
            return None;
        }
    }
}

pub fn open_process(pid: u32, access_right: Option<PROCESS_ACCESS_RIGHTS>) -> Option<OwnedHandle> {
    let ar = access_right.unwrap_or(PROCESS_ALL_ACCESS);
    let h: HANDLE = unsafe { OpenProcess(ar, FALSE, pid) };
    let oh = OwnedHandle::new(h)?;

    Some(oh)
}
