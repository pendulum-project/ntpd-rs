//! build.rs for statime-seccomp
fn main() {
    cc::Build::new()
        .file("seccomp.c")
        .compile("seccomp-trampoline.o");

    println!("cargo:rerun-if-changed=seccomp.c");
}
