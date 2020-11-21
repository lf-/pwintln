# pwintln

[this is campbell's fault](https://twitter.com/The6P4C/status/1329725624412381185)

you can upgrade your rust println functions across your entire codebase to all
be pwintln, which will automatically uwu all your messages for you.

## uwusage

```rust
use std::io::Write;
use cstr::cstr;
use std::os::raw::c_void;

let s = cstr!("ferris is my friend\n");
println!("i love rust");
    // outputs: "i love rust"
pwintln::install().unwrap();
unsafe { libc::write(1, s.as_ptr() as *const c_void, s.to_bytes().len()) };
    // outputs: "ferris is my friend"
println!("i love rust");
    // outputs: "i wuv wust"
std::io::stdout().write_all(b"i love rust\n").unwrap();
    // outputs: "i love rust"
```

## how

we replace the libc's write function with our own wrapper which uwus

## motivation

n/a

