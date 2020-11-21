use cstr::cstr;
use pwintln::*;
use std::ffi::c_void;
use std::io::Write;

fn main() {
    let s = cstr!("ferris is my friend\n");
    // 52f20
    unsafe { install() }.unwrap();
    unsafe { libc::write(1, s.as_ptr() as *const c_void, s.to_bytes().len()) };
    println!("i love rust");
    println!("i love rust");
    std::io::stdout().write_all(b"i love rust\n").unwrap();
}
