mod exceptional_condition_fd;
mod recv_message;
mod set_timestamping_options;
mod timestamping_config;

pub(crate) use exceptional_condition_fd::exceptional_condition_fd;
pub(crate) use recv_message::{
    control_message_space, receive_message, ControlMessage, MessageQueue,
};
pub(crate) use set_timestamping_options::set_timestamping_options;
pub(crate) use timestamping_config::TimestampingConfig;

/// Turn a C failure (-1 is returned) into a rust Result
pub(crate) fn cerr(t: libc::c_int) -> std::io::Result<libc::c_int> {
    match t {
        -1 => Err(std::io::Error::last_os_error()),
        _ => Ok(t),
    }
}
