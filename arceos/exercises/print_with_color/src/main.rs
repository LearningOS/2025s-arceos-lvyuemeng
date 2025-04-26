#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;
extern crate alloc;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    println!("\x1b[31m[WithColor]: Hello, Arceos!\x1b[0m");
}
