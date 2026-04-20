use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAllocEx, VirtualFreeEx,
};

// Owned Handle
pub struct HandleRAII {
    handle: HANDLE,
}

impl HandleRAII {
    pub fn new(h: HANDLE) -> Option<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self { handle: h })
        }
    }

    pub fn as_raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for HandleRAII {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// Remote Alloc
pub struct RemoteAllocRAII<'a> {
    process: &'a HandleRAII,
    addr: *mut c_void,
}

impl<'a> RemoteAllocRAII<'a> {
    pub fn new(
        process: &'a HandleRAII,
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Option<Self> {
        let addr = unsafe {
            VirtualAllocEx(
                process.as_raw(),
                std::ptr::null_mut(),
                size,
                MEM_RESERVE | MEM_COMMIT,
                protect,
            )
        };

        if addr.is_null() {
            None
        } else {
            Some(Self { process, addr })
        }
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.addr
    }
}

impl Drop for RemoteAllocRAII<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFreeEx(self.process.as_raw(), self.addr, 0, MEM_RELEASE);
        }
    }
}
