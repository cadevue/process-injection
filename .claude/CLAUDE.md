# CLAUDE.md — Top 10 Process Injection Techniques in Rust

## Project
Implementing all 10 process injection techniques from the Elastic blog survey in Rust.
Reference: https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process

## The 10 Techniques
1. Classic DLL Injection (CreateRemoteThread + LoadLibrary)
2. PE Injection (manual mapping + relocation fixups)
3. Process Hollowing / RunPE (CREATE_SUSPENDED → unmap → overwrite → resume)
4. Thread Execution Hijacking / SIR (SuspendThread → SetThreadContext → ResumeThread)
5. Hook Injection (SetWindowsHookEx)
6. Registry Injection (AppInit_DLLs, AppCertDlls, IFEO)
7. APC Injection + AtomBombing (QueueUserAPC, atom tables)
8. Extra Window Memory Injection (SetWindowLong + SendNotifyMessage on Shell_TrayWnd)
9. Shim Injection (sdb / Application Compatibility)
10. IAT Hooking & Inline Hooking (userland rootkits)

## Rules — READ THESE FIRST

### Implementation
- **DO NOT write implementation code.** Not a single line. No "here's how you'd do it" snippets.
- **DO NOT touch any `.rs` files.** No creating, editing, or suggesting ready-to-paste code blocks.
- Instead: point me to articles, blog posts, YouTube videos, MSDN docs, GitHub repos (as reading reference), and explain concepts at a high level so I understand the "why" and implement it myself.
- Acceptable: explaining a WinAPI function's signature/purpose, describing the flow of an injection technique, clarifying Rust FFI concepts verbally.

### Dependency Policy
- **No injection/hooking crates** (no `dll-syringe`, `retour`, `detour-rs`, `pelite` for injection, etc.)
- Utility crates are tolerated if truly needed (e.g., `clap` for CLI, `anyhow`/`thiserror` for errors) but **fewer is better, zero is best.**
- All Windows API calls go through raw FFI: `windows-sys` or hand-written `extern "system"` blocks.
- The goal is to understand the OS internals, not wrap them in abstractions.

### How to Help Me
1. **Explain the technique** — what it does, why it works, what the OS-level flow looks like.
2. **List the WinAPI functions involved** — names, MSDN links, parameter meanings.
3. **Link learning resources** — blogs, conference talks, source repos to study (not to copy).
4. **Warn about pitfalls** — common crashes, detection vectors, Rust-specific FFI gotchas (alignment, null terminators, lifetime of raw pointers, etc.)
5. **Never hand me the answer.** If I'm stuck, give me a smaller hint, not the solution.

## Tech Stack
- Language: Rust (stable, latest)
- Target: Windows x86_64
- FFI: `windows-sys` crate or raw `extern "system"` — no high-level wrappers
- Build: cargo, standard toolchain

## Key Resources
- Main reference: Elastic blog (linked above)
- MSDN/Learn: https://learn.microsoft.com/en-us/windows/win32/api/
- Rust FFI: https://doc.rust-lang.org/nomicon/ffi.html
- windows-sys docs: https://docs.rs/windows-sys/latest/windows_sys/