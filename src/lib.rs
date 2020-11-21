#![allow(non_snake_case)]
//! Warning: this library is programmed as a meme. You should **not** use it.
//! Only Linux is supported, because it lets us have the worst ideas the fastest.

use std::convert::TryInto;
use std::ffi::CStr;
use std::slice;
use xmas_elf::{
    dynamic, header::parse_header, program, program::parse_program_header, sections, symbol_table,
    symbol_table::Entry, ElfFile, P64,
};

macro_rules! auxval {
    ($name:ident, $cons:ident) => {
        fn $name() -> usize {
            unsafe { libc::getauxval(libc::$cons) as usize }
        }
    };
}

auxval!(ph_entries, AT_PHNUM);
auxval!(ph_entry_size, AT_PHENT);
auxval!(phdr_base, AT_PHDR);

// reimplemented from https://stackoverflow.com/a/27304692
#[cfg(target_pointer_width = "64")]
unsafe fn get_headers() -> &'static [u8] {
    // so this is wrong actually, but my library can't do it properly (need to parse the
    // phdr->p_vaddr out but we can't parse program headers until we have program headers...) so
    // let's just hardcode it lol
    // consider:
    // https://github.com/rofl0r/musl/blob/master/src/ldso/dl_iterate_phdr.c
    let size = ph_entries() * ph_entry_size() + 0x40;
    let headers = phdr_base() - 0x40;
    // safety: lol
    slice::from_raw_parts(headers as *const u8, size as usize)
}

pub fn parse_sElf() -> Option<ElfFile<'static>> {
    let headers = unsafe { get_headers() };
    let ef = ElfFile::new(headers).unwrap();
    let phdr = ef
        .program_iter()
        .find(|ph| ph.get_type() == Ok(program::Type::Phdr))
        .unwrap();
    // base address we're loaded at
    let prog_base = phdr_base() - phdr.virtual_addr() as usize;
    println!("BASE: {:x}", prog_base);

    let dynamic = ef
        .program_iter()
        .find(|ph| ph.get_type() == Ok(program::Type::Dynamic))
        .unwrap();

    let dynamics = unsafe {
        slice::from_raw_parts(
            (prog_base as *const u8).offset(dynamic.virtual_addr().try_into().unwrap()),
            dynamic.mem_size() as usize,
        )
    };
    let dynamics: &[dynamic::Dynamic<P64>] = zero::read_array(dynamics);

    let jmprel = dynamics
        .iter()
        .find(|d| d.get_tag() == Ok(dynamic::Tag::JmpRel))
        .unwrap();
    let jmprellen = dynamics
        .iter()
        .find(|d| d.get_tag() == Ok(dynamic::Tag::PltRelSize))
        .unwrap();
    let jmprel: &[sections::Rela<P64>] = zero::read_array(unsafe {
        slice::from_raw_parts(
            jmprel.get_ptr().unwrap() as *const u8,
            jmprellen.get_val().unwrap() as usize,
        )
    });

    let strtab = dynamics
        .iter()
        .find(|d| d.get_tag() == Ok(dynamic::Tag::StrTab))
        .unwrap();
    let strtablen = dynamics
        .iter()
        .find(|d| d.get_tag() == Ok(dynamic::Tag::StrSize))
        .unwrap();
    let strtab: &[u8] = unsafe {
        slice::from_raw_parts(
            strtab.get_ptr().unwrap() as *const u8,
            strtablen.get_val().unwrap() as usize,
        )
    };

    let symtab = dynamics
        .iter()
        .find(|d| d.get_tag() == Ok(dynamic::Tag::SymTab))
        .unwrap()
        .get_ptr()
        .unwrap() as *const symbol_table::Entry64;

    let idx = 0usize;
    let rela = &jmprel[idx];
    let symidx = rela.get_symbol_table_index();
    let sym = unsafe {
        // safety: lol
        &*symtab.offset(symidx as isize)
    };
    // rust makes it more of a pain in the butt to do this safely so sod it
    // dumb unsafety time!
    let symname = unsafe { CStr::from_ptr(strtab[sym.name() as usize..].as_ptr() as *const i8) };

    println!("{:x?}", dynamics);
    println!("{:?}", symname);
    todo!()
}
