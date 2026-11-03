//! Process-owned privilege inspection and dropping.

use impulse_config::runtime::RuntimeConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivilegeDropTarget {
    pub(crate) user: String,
    pub(crate) group: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessPrivilegeState {
    effective_uid: libc::uid_t,
    has_net_bind_service_capability: bool,
}

impl ProcessPrivilegeState {
    pub(crate) fn can_bind_privileged_ports(self) -> bool {
        self.effective_uid == 0 || self.has_net_bind_service_capability
    }

    fn can_drop_privileges(self) -> bool {
        self.effective_uid == 0
    }
}

pub(crate) fn current_process_privilege_state() -> ProcessPrivilegeState {
    ProcessPrivilegeState {
        effective_uid: unsafe {
            // SAFETY: simple libc getter.
            libc::geteuid()
        },
        has_net_bind_service_capability: has_effective_net_bind_service_capability(),
    }
}

pub(crate) fn apply_process_privilege_drop(
    startup_privileges: ProcessPrivilegeState,
    runtime_config: &RuntimeConfig,
) -> Result<Option<PrivilegeDropTarget>, String> {
    if !startup_privileges.can_drop_privileges() || !runtime_config.security.privileges.enabled {
        return Ok(None);
    }

    let user = runtime_config.security.privileges.user.trim();
    let group = runtime_config.security.privileges.group.trim();
    drop_privileges(user, group)?;

    Ok(Some(PrivilegeDropTarget {
        user: user.to_string(),
        group: group.to_string(),
    }))
}

#[cfg(target_os = "linux")]
fn has_effective_net_bind_service_capability() -> bool {
    use std::io::{BufRead, BufReader};

    let file = match std::fs::File::open("/proc/self/status") {
        Ok(file) => file,
        Err(_) => return false,
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else {
            return false;
        };
        if let Some(has_capability) =
            has_effective_net_bind_service_capability_from_status_line(&line)
        {
            return has_capability;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn has_effective_net_bind_service_capability_from_status_line(line: &str) -> Option<bool> {
    const CAP_NET_BIND_SERVICE_BIT: u32 = 10;

    let value = line.strip_prefix("CapEff:\t")?;
    let mask = u64::from_str_radix(value.trim(), 16).ok()?;
    Some((mask & (1u64 << CAP_NET_BIND_SERVICE_BIT)) != 0)
}

#[cfg(not(target_os = "linux"))]
fn has_effective_net_bind_service_capability() -> bool {
    false
}

#[cfg(unix)]
fn drop_privileges(user: &str, group: &str) -> Result<(), String> {
    use std::{ffi::CString, io};

    const DEFAULT_LOOKUP_BUF_LEN: usize = 16 * 1024;
    const MAX_LOOKUP_BUF_LEN: usize = 1024 * 1024;

    fn initial_lookup_buf_len(selector: libc::c_int) -> usize {
        let size = unsafe {
            // SAFETY: sysconf is thread-safe and does not require additional invariants.
            libc::sysconf(selector)
        };
        if size > 0 {
            size as usize
        } else {
            DEFAULT_LOOKUP_BUF_LEN
        }
    }

    fn lookup_group_gid(c_group: &CString, group: &str) -> Result<libc::gid_t, String> {
        let mut buf_len = initial_lookup_buf_len(libc::_SC_GETGR_R_SIZE_MAX);
        loop {
            let mut entry = std::mem::MaybeUninit::<libc::group>::uninit();
            let mut result: *mut libc::group = std::ptr::null_mut();
            let mut buf = vec![0 as libc::c_char; buf_len];
            let rc = unsafe {
                // SAFETY: pointers are valid for the provided buffer and output slots.
                libc::getgrnam_r(
                    c_group.as_ptr(),
                    entry.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == 0 {
                if result.is_null() {
                    return Err(format!("group '{}' not found", group));
                }
                let entry = unsafe {
                    // SAFETY: successful lookup initializes `entry`.
                    entry.assume_init()
                };
                return Ok(entry.gr_gid);
            }
            if rc == libc::ERANGE && buf_len < MAX_LOOKUP_BUF_LEN {
                buf_len = (buf_len * 2).min(MAX_LOOKUP_BUF_LEN);
                continue;
            }
            return Err(format!(
                "failed to resolve group '{}': {}",
                group,
                io::Error::from_raw_os_error(rc)
            ));
        }
    }

    fn lookup_user_uid(c_user: &CString, user: &str) -> Result<libc::uid_t, String> {
        let mut buf_len = initial_lookup_buf_len(libc::_SC_GETPW_R_SIZE_MAX);
        loop {
            let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let mut buf = vec![0 as libc::c_char; buf_len];
            let rc = unsafe {
                // SAFETY: pointers are valid for the provided buffer and output slots.
                libc::getpwnam_r(
                    c_user.as_ptr(),
                    entry.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == 0 {
                if result.is_null() {
                    return Err(format!("user '{}' not found", user));
                }
                let entry = unsafe {
                    // SAFETY: successful lookup initializes `entry`.
                    entry.assume_init()
                };
                return Ok(entry.pw_uid);
            }
            if rc == libc::ERANGE && buf_len < MAX_LOOKUP_BUF_LEN {
                buf_len = (buf_len * 2).min(MAX_LOOKUP_BUF_LEN);
                continue;
            }
            return Err(format!(
                "failed to resolve user '{}': {}",
                user,
                io::Error::from_raw_os_error(rc)
            ));
        }
    }

    let c_group = CString::new(group).map_err(|_| "group contains NUL byte".to_string())?;
    let c_user = CString::new(user).map_err(|_| "user contains NUL byte".to_string())?;

    let gid = lookup_group_gid(&c_group, group)?;
    let uid = lookup_user_uid(&c_user, user)?;

    let clear_groups_rc = unsafe {
        // SAFETY: passing null pointer with length 0 clears supplementary groups.
        libc::setgroups(0, std::ptr::null())
    };
    if clear_groups_rc != 0 {
        return Err("failed to clear supplementary groups".to_string());
    }

    let setgid_rc = unsafe {
        // SAFETY: gid resolved from getgrnam_r above.
        libc::setgid(gid)
    };
    if setgid_rc != 0 {
        return Err(format!("failed to drop group privileges to '{}'", group));
    }

    let setuid_rc = unsafe {
        // SAFETY: uid resolved from getpwnam_r above.
        libc::setuid(uid)
    };
    if setuid_rc != 0 {
        return Err(format!("failed to drop user privileges to '{}'", user));
    }

    let effective_uid = unsafe {
        // SAFETY: simple libc getter.
        libc::geteuid()
    };
    if effective_uid == 0 {
        return Err("privilege drop verification failed: still running as root".to_string());
    }

    Ok(())
}

#[cfg(not(unix))]
fn drop_privileges(_user: &str, _group: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use impulse_config::{config::Config, runtime::RuntimeConfig};

    use super::{ProcessPrivilegeState, apply_process_privilege_drop};

    fn minimal_runtime_config() -> RuntimeConfig {
        let yaml = r#"
listen:
  tls:
    cert: "/tmp/tls/default.pem"
    key: "/tmp/tls/default.key"
upstream:
  api:
    route:
      path_prefix: "/"
    backends:
      - id: backend1
        address: "http://127.0.0.1:7001"
"#;
        let config: Config = serde_yaml::from_str(yaml).expect("minimal config");
        RuntimeConfig::from_config(&config).expect("runtime config")
    }

    fn privilege_state(effective_uid: libc::uid_t) -> ProcessPrivilegeState {
        ProcessPrivilegeState {
            effective_uid,
            has_net_bind_service_capability: false,
        }
    }

    #[test]
    fn skips_drop_when_startup_is_not_root() {
        let runtime_config = minimal_runtime_config();
        let result =
            apply_process_privilege_drop(privilege_state(1000), &runtime_config).expect("no-op");
        assert!(result.is_none());
    }

    #[test]
    fn attempts_drop_when_effective_uid_is_root() {
        let mut runtime_config = minimal_runtime_config();
        runtime_config.security.privileges.user = format!("missing-user-{}", std::process::id());
        runtime_config.security.privileges.group = format!("missing-group-{}", std::process::id());

        let result = apply_process_privilege_drop(privilege_state(0), &runtime_config);
        assert!(result.is_err());
    }

    #[test]
    fn skips_drop_when_control_is_disabled() {
        let mut runtime_config = minimal_runtime_config();
        runtime_config.security.privileges.enabled = false;

        let result =
            apply_process_privilege_drop(privilege_state(0), &runtime_config).expect("no-op");
        assert!(result.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unknown_group_or_user_before_system_calls() {
        let mut runtime_config = minimal_runtime_config();
        runtime_config.security.privileges.user = "nobody".to_string();
        runtime_config.security.privileges.group = format!("missing-group-{}", std::process::id());

        let result = apply_process_privilege_drop(privilege_state(0), &runtime_config);
        assert!(result.is_err());

        runtime_config.security.privileges.user = format!("missing-user-{}", std::process::id());
        runtime_config.security.privileges.group = "nogroup".to_string();

        let result = apply_process_privilege_drop(privilege_state(0), &runtime_config);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_cap_eff_net_bind_service_bit() {
        assert_eq!(
            super::has_effective_net_bind_service_capability_from_status_line(
                "CapEff:\t0000000000000400"
            ),
            Some(true)
        );
        assert_eq!(
            super::has_effective_net_bind_service_capability_from_status_line(
                "CapEff:\t0000000000000000"
            ),
            Some(false)
        );
    }
}
