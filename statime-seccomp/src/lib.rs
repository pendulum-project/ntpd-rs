//! Our seccomp bindings consist of two parts:
//! - A high-level interface written in C which ensures that the platform compiler will insert all the correct sycall numbers.
//! - A lightweight Rust wrapper around this interface.
//!
//! Example:
//! ```should_panic
//! fn main() {
//!     statime_seccomp::KillProcess.enable().unwrap();
//! }
//! ```
//!
use std::io::{Error, Result};

#[cfg(not(target_os = "linux"))]
compile_error!("seccomp filtering is only for Linux targets");

#[link(name = "seccomp")]
unsafe extern "C" {
    static statime_kill_thread: u32;
    static statime_kill_process: u32;
    static statime_trap: u32;
    static statime_err: u32;
    static statime_log: u32;

    fn statime_sandbox(def_action: u32) -> std::ffi::c_int;
}

/// What action should be taken for system calls that are not explicitly allowed. The options are:
pub enum Seccomp {
    /// Kill the calling thread
    KillThread,
    /// Kill the entire process
    KillProcess,
    /// Trigger a trap (that can be caught)
    Trap,
    /// Make the syscall result in an EPERM error
    Fail,
    /// Allow the call but log it
    Log,
}

pub use Seccomp::*;

impl Seccomp {
    fn into_u32(self) -> u32 {
        //SAFETY: The referenced extern static's are declared as "const" and never
        //have their address taken, so data races and aliasing does not occur.
        unsafe {
            match self {
                Seccomp::KillThread => statime_kill_thread,
                Seccomp::KillProcess => statime_kill_process,
                Seccomp::Trap => statime_trap,
                Seccomp::Fail => statime_err,
                Seccomp::Log => statime_log,
            }
        }
    }

    /// Load the statime seccomp filter into the kernel.
    ///
    /// # Panics
    ///
    /// Panics if any of the libseccomp functions do not adhere to their specification.
    ///
    /// # Errors
    ///
    /// Will contain the the first error that is returned from a libseccomp function;
    /// this is fatal and means the seccomp filter has not been loaded.
    pub fn enable(self) -> Result<()> {
        let scmp_action = self.into_u32();

        //SAFETY: the statime_sandbox function is always safe to call.
        match unsafe { statime_sandbox(scmp_action) } {
            0 => Ok(()),

            x if x < 0 => Err(Error::from_raw_os_error(-x)),

            _ => panic!("libseccomp returned a positive error"),
        }
    }
}
