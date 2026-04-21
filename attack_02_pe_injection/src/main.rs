use std::fs;
use std::ptr;

use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER; 

fn main() {
    // Extract Payload Path
    let dll_path_arg = std::env::args().nth(1).expect("Usage: attack_02_pe_injection.exe <payload dll path>");
    let dll_path = std::path::PathBuf::from(dll_path_arg).canonicalize().expect("DLL path is invalid or not found");

    // Read PE File
    let pe = fs::read(dll_path).expect("Failed to read the payload PE");
    let dos_h = unsafe { ptr::read_unaligned(pe.as_ptr() as *const IMAGE_DOS_HEADER) };

    let magic = dos_h.e_magic;
    let lfanew = dos_h.e_lfanew;

    if magic != 0x5A4D  {
        println!("PE magic bytes does not match (expected: 0x5A4D <MZ>, found: {:#x})", magic);
        return;
    }

    let nt_h = unsafe { ptr::read_unaligned(pe.as_ptr().add(lfanew as usize) as *const IMAGE_NT_HEADERS64) };

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
    let opt_magic_str = match opt_magic {
        0x10B => "PE32",
        0x20B => "PE32+",
        _ => "unknown",
    };

    let machine = nt_h.FileHeader.Machine;
    let machine_str = match machine {
        0x8664 => "x64 (AMD64)",
        0x014C => "x86 (i386)",
        0xAA64 => "ARM64",
        _ => "unknown",
    };

    let sections_count = nt_h.FileHeader.NumberOfSections;
    let img_base = nt_h.OptionalHeader.ImageBase;
    let size_of_img = nt_h.OptionalHeader.SizeOfImage;

    println!("\nPE Information");
    println!();
    println!("[DOS Header]");
    println!("  e_magic      : {:#06x}  ({:?})", magic, "MZ");
    println!("  e_lfanew     : {:#x}  (NT header offset)", lfanew);
    println!();
    println!("[NT Headers]");
    println!("  Signature    : {:#010x}  (\"PE\\0\\0\")", sig);
    println!();
    println!("[File Header]");
    println!("  Machine      : {:#06x}  ({})", machine, machine_str);
    println!("  Sections     : {}", sections_count);
    println!();
    println!("[Optional Header]");
    println!("  Magic        : {:#06x}  ({})", opt_magic, opt_magic_str);
    println!("  ImageBase    : {:#018x}", img_base);
    println!("  SizeOfImage  : {:#x}  ({} bytes)", size_of_img, size_of_img);
}
