extern crate cc;

use cc::Build;

fn main() {
    Build::new()
        .file("src/linux.c")
        .warnings(true)
        .compile("tundevice");
}
