use std::ffi::c_void;
use std::ptr::null_mut;

use common::OwnedHandle;
use windows_sys::Win32::Foundation::{HANDLE, HINSTANCE, TRUE};
use windows_sys::Win32::System::Threading::CreateThread;

use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW};
use windows_sys::core::BOOL;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut c_void) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        let h: HANDLE = unsafe {
            CreateThread(
                null_mut(),
                0,
                Some(attach_routine),
                null_mut(),
                0,
                null_mut(),
            )
        };
        let _ = OwnedHandle::new(h); // Automatic cleanup
    }

    TRUE
}

unsafe extern "system" fn attach_routine(_: *mut c_void) -> u32 {
    let title: Vec<u16> = "Warning".encode_utf16().chain(Some(0)).collect();
    let message: Vec<u16> = "Your spaceship has been hijacked!"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        // Create a message box
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONWARNING,
        );
    };
    0
}
