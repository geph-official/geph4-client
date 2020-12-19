#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(target_os = "windows")]
fn main() {
    windows::main()
}
