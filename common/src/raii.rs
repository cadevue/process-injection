use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualFreeEx
};

// Owned Handle
pub struct ManagedHandle {
    handle: HANDLE,
}

impl ManagedHandle {
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

impl Drop for ManagedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// Local Alloc
pub struct ManagedVirtualAlloc {
    addr: *mut c_void,
}

impl ManagedVirtualAlloc {
    pub fn new(
        size: usize,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> Option<Self> {
        let addr = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                size,
                MEM_RESERVE | MEM_COMMIT,
                protect,
            )
        };

        if addr.is_null() {
            None
        } else {
            Some(Self { addr })
        }
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.addr
    }
}

impl Drop for ManagedVirtualAlloc {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.addr, 0, MEM_RELEASE);
        }
    }
}


// Remote Alloc
pub struct ManagedVirtualAllocEx<'a> {
    process: &'a ManagedHandle,
    addr: *mut c_void,
}

impl<'a> ManagedVirtualAllocEx<'a> {
    pub fn new(
        process: &'a ManagedHandle,
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

impl Drop for ManagedVirtualAllocEx<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFreeEx(self.process.as_raw(), self.addr, 0, MEM_RELEASE);
        }
    }
}
