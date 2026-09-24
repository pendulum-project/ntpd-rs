//! Our seccomp bindings consist of two parts:
//! - A high-level interface written in C which ensures that the platform compiler will insert all the correct sycall numbers.
//! - A lightweight Rust wrapper around this interface.
//!
//! Example:
//! ```
//! statime_seccomp::KillProcess.enable().expect("could not enable seccomp filter");
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

#[cfg(test)]
mod test {
    use super::*;

    fn not_allowed() -> std::io::Result<()> {
        std::env::set_current_dir(".").map(|_| ())
    }

    fn allowed() -> std::io::Result<()> {
        std::net::UdpSocket::bind("0.0.0.0:0").map(|_| ())
    }

    #[test]
    fn cannot_downgrade() {
        Fail.enable().unwrap();
        assert!(Log.enable().is_err());
    }

    #[test]
    fn allowlisted_functions_are_fine() {
        Fail.enable().unwrap();
        assert!(allowed().is_ok());
    }

    #[test]
    fn blocklisted_functions_are_stopped() {
        Fail.enable().unwrap();
        assert!(not_allowed().is_err());
    }

    #[test]
    fn blocklisted_functions_are_fine_when_logged() {
        Log.enable().unwrap();
        assert!(not_allowed().is_ok());
    }

    #[test]
    fn thread_is_stopped() {
        // Rust doesn't expect a thread to terminate suddenly; this causes a panic in the std lib;
        // catch that panic to demonstrate that the thread is stopped but the entire process isn't.
        let result = std::panic::catch_unwind(move || {
            let handle = std::thread::spawn(|| {
                KillThread.enable().unwrap();
                let _ = not_allowed();
            });
            let _ = handle.join();
        });

        assert!(result.is_err());
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    #[test]
    fn process_is_stopped() {
        for catchable in [true, false] {
            unsafe {
                //NOTE on async-signal safety: yes, there will be threads running, but:
                // - not_allowed() is async-signal-safe
                // - see https://github.com/seccomp/libseccomp/pull/390 for seccomp
                // - this is test code
                match libc::fork() {
                    0 => {
                        // we are the child
                        unsafe extern "C" fn exit42(_: std::ffi::c_int) {
                            unsafe { libc::_exit(42) }
                        }
                        libc::signal(libc::SIGSYS, exit42 as *const () as libc::sighandler_t);

                        if catchable { Trap } else { KillProcess }.enable().unwrap();
                        let _ = not_allowed();

                        unreachable!();
                    }
                    child_pid => {
                        // we are the parent
                        let mut status = 0;
                        assert_eq!(libc::wait(&mut status), child_pid);

                        if catchable {
                            assert!(libc::WIFEXITED(status));
                            assert_eq!(libc::WEXITSTATUS(status), 42);
                        } else {
                            assert!(libc::WIFSIGNALED(status));
                            assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
                        }
                    }
                };
            }
        }
    }
}
