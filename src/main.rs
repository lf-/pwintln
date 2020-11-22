use cstr::cstr;
use pwintln::*;
use std::ffi::c_void;
use std::io::Write;

fn main() {
    let s = cstr!("ferris is my friend\n");
    install().unwrap();
    unsafe { libc::write(1, s.as_ptr() as *const c_void, s.to_bytes().len()) };
    println!("i love rust");
    println!("i love rust");
    std::io::stdout().write_all(b"i love rust\n").unwrap();

    eprintln!("ferris is my best friend");
    uwu_stderr(true);
    eprintln!("ferris is my best friend");
}
