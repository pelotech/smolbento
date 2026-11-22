//! Taking the listening socket from the service manager.

use std::net::TcpListener;

/// The listening socket handed over by launchd (macOS) or systemd, or `None` when not socket-activated.
///
/// launchd: the job's `Listeners` socket. systemd: fd 3 when `LISTEN_PID` is this process and `LISTEN_FDS` is 1.
pub fn activated_listener() -> std::io::Result<Option<TcpListener>> {
    #[cfg(target_os = "macos")]
    if let Some(l) = launchd_listener()? {
        return Ok(Some(l));
    }
    systemd_listener()
}

fn systemd_listener() -> std::io::Result<Option<TcpListener>> {
    use std::os::fd::FromRawFd;
    let ours = std::env::var("LISTEN_PID").is_ok_and(|p| p == std::process::id().to_string());
    if !ours || std::env::var("LISTEN_FDS").as_deref() != Ok("1") {
        return Ok(None);
    }
    // SAFETY: systemd passed us fd 3 as a listening socket, and nothing else in this process owns it.
    let l = unsafe { TcpListener::from_raw_fd(3) };
    l.set_nonblocking(false)?;
    Ok(Some(l))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const std::os::raw::c_char,
        fds: *mut *mut std::os::raw::c_int,
        cnt: *mut usize,
    ) -> std::os::raw::c_int;
    fn free(p: *mut std::ffi::c_void);
}

#[cfg(target_os = "macos")]
fn launchd_listener() -> std::io::Result<Option<TcpListener>> {
    use std::os::fd::FromRawFd;
    if std::env::var_os("XPC_SERVICE_NAME").is_none_or(|v| v == "0") {
        return Ok(None);
    }
    let name = c"Listeners";
    let mut fds: *mut std::os::raw::c_int = std::ptr::null_mut();
    let mut cnt: usize = 0;
    // SAFETY: on success launchd allocates `cnt` descriptors at `fds`, which we own and free.
    let rc = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut cnt) };
    if rc != 0 || cnt == 0 {
        return Ok(None);
    }
    // SAFETY: `cnt >= 1`, so the first descriptor is valid; we take it and free the array.
    let l = unsafe {
        let fd = *fds;
        free(fds.cast());
        TcpListener::from_raw_fd(fd)
    };
    l.set_nonblocking(false)?;
    Ok(Some(l))
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_activation_environment_means_no_listener() {
        assert!(super::activated_listener().unwrap().is_none());
    }
}
