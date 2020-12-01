#![allow(non_snake_case)]
//! Warning: this library is programmed as a meme. You should **not** use it.
//! Only Linux is supported, because it lets us have the worst ideas the fastest.

use std::convert::TryInto;
use std::mem;
use std::os::raw::*;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use owoify::OwOifiable;

use goblin::elf;
use goblin::strtab;

use elf::dynamic::dyn64;
use elf::dynamic::*;
use elf::program_header::program_header64::ProgramHeader;
use elf::program_header::*;
use elf::reloc::reloc64;
use elf::sym::sym64;

static BORING_WRITE: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static STDOUT_MACHINERY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static STDERR_MACHINERY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static UWU_STDOUT: AtomicBool = AtomicBool::new(true);
static UWU_STDERR: AtomicBool = AtomicBool::new(false);

// only uwu stuff that comes from println!/eprintln!, not manual writes
const STDIO_NAMES: &[&str] = &[
    "std::io::stdio::print_to",
    "std::io::stdio::_print",
    "std::io::stdio::_eprint",
];

/// grabs a backtrace, managing the given atomic, and return a tuple of (found print machinery
/// address, backtrace)
fn grab_bt(machinery: &AtomicPtr<c_void>) -> (*mut c_void, backtrace::Backtrace) {
    // atomic: we don't care about the surrounding memory at all; it's not even a problem if we
    // write twice!
    let mut cached_print_machinery = machinery.load(Ordering::Relaxed);

    // if we have not already found the print machinery, we need a textual backtrace
    if cached_print_machinery.is_null() {
        let bt = backtrace::Backtrace::new();
        for fra in bt.frames() {
            for sym in fra.symbols() {
                let pretty = format!("{}", sym.name().unwrap());
                if STDIO_NAMES.iter().any(|n| pretty.starts_with(n)) {
                    // eprintln!("found the print uwu {:?}", sym);
                    let print_addr = fra.symbol_address();
                    machinery.compare_and_swap(ptr::null_mut(), print_addr, Ordering::Relaxed);
                    cached_print_machinery = print_addr;
                }
            }
            // eprintln!("frame uwu! {:?} {:?}", fra, fra.symbols());
        }
        (cached_print_machinery, bt)
    } else {
        // we have the print machinery so we can take an unresolved backtrace
        (
            cached_print_machinery,
            backtrace::Backtrace::new_unresolved(),
        )
    }
}

/// Our uwu-ized wrapper around libc's `write(2)`.
extern "C" fn write_uwu(fd: c_int, buf: *const c_void, count: usize) -> isize {
    let write = BORING_WRITE.load(Ordering::Relaxed);
    if write.is_null() {
        // oh shit
        std::process::abort();
    }
    let write: CWrite = unsafe { mem::transmute(write) };

    // check if this fd can be uwu'd
    let is_uwuable = match fd {
        // stdout
        1 => UWU_STDOUT.load(Ordering::Relaxed),
        // stderr
        2 => UWU_STDERR.load(Ordering::Relaxed),
        _ => false,
    };

    if !is_uwuable {
        return write(fd, buf, count);
    }

    // now find out who called us
    let (cached_print_machinery, bt) = grab_bt(if fd == 1 {
        &STDOUT_MACHINERY
    } else if fd == 2 {
        &STDERR_MACHINERY
    } else {
        // unreachable
        std::process::abort();
    });

    // now find if we need to uwu
    let should_uwu = !cached_print_machinery.is_null()
        && bt
            .frames()
            .iter()
            .any(|f| f.symbol_address() == cached_print_machinery);

    if !should_uwu {
        // just call write
        write(fd, buf, count)
    } else {
        // uwu time!!!!
        // get the printed string
        let s: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, count) };
        let s = std::str::from_utf8(s);
        if let Ok(s) = s {
            let uwu = s.to_string().owoify();
            let uwu = uwu.as_bytes();
            let mut writing = &uwu[..];
            while !writing.is_empty() {
                let wrote = write(fd, writing.as_ptr() as *const c_void, writing.len());
                if wrote < 0 {
                    // oh no write did a fucky wucky, report it
                    return wrote;
                }
                writing = &writing[wrote as usize..];
            }
            // pretend to have written no more than the `count`
            // XXX: this is probably not 100% perfect.
            count as isize
        } else {
            // looks like we did a fucky wucky. oh well, just send it to stdout
            write(fd, buf, count)
        }
    }
}

/// 4k pages
const PAGE_SIZE: usize = 0x1000;

/// OwO whats this
///
/// Calling this function makes all `println!()` calls uwu-ize their outputs
pub fn install() -> Option<()> {
    let write = find_write()?;
    // safety: it's from my code and therefore is perfect
    let writeaddr = unsafe { *write as *mut () };
    // this should be thread safe if we only store if it's null
    // whoever gets to this first will have a valid pointer
    // atomic: it's not a problem if the update to the function pointer is delayed as any hit of
    // the write_uwu function will still get this original pointer that was stored atomically
    // (the invariant we care about)
    let v = BORING_WRITE.compare_and_swap(ptr::null_mut(), writeaddr, Ordering::Relaxed);
    if v.is_null() {
        // eprintln!("installing");
        let write_page = (write as usize) & !(PAGE_SIZE - 1);
        // safety: lol
        unsafe {
            libc::mprotect(
                write_page as *mut c_void,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        // we were the thread that successfully wrote, so we should update the PLT
        unsafe { *write = write_uwu };
        Some(())
    } else {
        // even if we lost, someone installed successfully
        // so it is not a failure
        Some(())
    }
}

/// Sets the uwu enabling of stdout
pub fn uwu_stdout(should: bool) {
    UWU_STDOUT.store(should, Ordering::Relaxed);
}

/// Sets the uwu enabling of stdout
pub fn uwu_stderr(should: bool) {
    UWU_STDERR.store(should, Ordering::Relaxed);
}

type CWrite = extern "C" fn(fd: c_int, buf: *const c_void, count: usize) -> isize;

macro_rules! auxval {
    ($name:ident, $cons:ident) => {
        fn $name() -> usize {
            unsafe { libc::getauxval(libc::$cons) as usize }
        }
    };
}

auxval!(ph_entries, AT_PHNUM);
auxval!(phdr_base, AT_PHDR);

// some inspiration from https://stackoverflow.com/a/27304692

// might as well fail to compile on 32 bit here, it's as good a place as any
#[cfg(target_pointer_width = "64")]
unsafe fn get_headers() -> &'static [ProgramHeader] {
    // this was helpful:
    // https://github.com/rofl0r/musl/blob/master/src/ldso/dl_iterate_phdr.c

    ProgramHeader::from_raw_parts(phdr_base() as *const ProgramHeader, ph_entries())
}

fn find_write() -> Option<*mut CWrite> {
    // grab the program headers which will tell us where our elf stuff is
    let headers = unsafe { get_headers() };
    let phdr = headers.iter().find(|h| h.p_type == PT_PHDR)?;
    // base address we're loaded at
    let prog_base = phdr_base() - phdr.p_vaddr as usize;

    // safety: i think if someone's messing up loading my executable i have bigger problems to deal
    // with
    let dynamic = unsafe { dyn64::from_phdrs(prog_base, headers) }?;

    // DynamicInfo tries to be smart and convert the vm addresses to file addresses. shame we're
    // working on an mmapped executable, namely ourselves. time 2 do it ourselves
    //
    // dyn64::DynamicInfo::new(dynamic, headers);
    let mut rela = None;
    let mut relasz = None;
    let mut strtab = None;
    let mut strtabsz = None;
    let mut symtab = None;
    for dynentry in dynamic {
        let v = Some(dynentry.d_val);
        match dynentry.d_tag {
            DT_RELA => rela = v,
            DT_RELASZ => relasz = v,
            DT_STRTAB => strtab = v,
            DT_STRSZ => strtabsz = v,
            DT_SYMTAB => symtab = v,
            _ => (),
        }
    }
    let symtab = symtab? as *const sym64::Sym;
    let rela = unsafe { reloc64::from_raw_rela(rela? as *const reloc64::Rela, relasz? as usize) };

    let strtab = unsafe {
        strtab::Strtab::from_raw(
            strtab.unwrap() as *const u8,
            strtabsz.unwrap() as usize,
            0x0, // i think this is the delimiter?
        )
    };

    let mut write = None;
    for rel in rela.iter() {
        // ELF64_R_SYM(r_info)
        let ridx = rel.r_info >> 32;
        let sym = unsafe { *symtab.offset(ridx.try_into().ok()?) };
        let name = strtab.get(sym.st_name as usize); // lol
        if let Some(Ok(v)) = name {
            if v != "write" {
                continue;
            }
        } else {
            continue;
        }
        write = unsafe {
            Some(mem::transmute(
                prog_base.checked_add(rel.r_offset as usize)?,
            ))
        };
        // println!("rela! {:?}", rel);
        // println!("with name! {:?}", name);
    }
    // println!("dynamic: {:#?}", dynamic);
    write
    // todo!()
}

#[cfg(doctest)]
mod doctest {
    use doc_comment::doctest;
    doctest!("../README.md");
}
