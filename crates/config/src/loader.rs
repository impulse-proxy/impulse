use serde_yaml::{Mapping, Value};

use crate::{
    bounded_file::{BoundedFileReadError, read_file_with_limit},
    config::{CURRENT_CONFIG_VERSION, Config, SUPPORTED_CONFIG_VERSIONS},
};

const MAX_CONFIG_FILE_BYTES: u64 = 4 * 1024 * 1024;

pub fn read_config(filename: &str) -> Result<Config, String> {
    let bytes = match read_file_with_limit(filename, MAX_CONFIG_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(BoundedFileReadError::Io(err)) => {
            return Err(format!(
                "Failed to read config file '{}': {}",
                filename, err
            ));
        }
        Err(BoundedFileReadError::NotAFile) => {
            return Err(format!(
                "Failed to read config file '{}': not a file",
                filename
            ));
        }
        Err(BoundedFileReadError::TooLarge) => {
            return Err(format!(
                "Failed to read config file '{}': exceeds maximum supported size ({} bytes)",
                filename, MAX_CONFIG_FILE_BYTES
            ));
        }
    };
    let text = String::from_utf8(bytes)
        .map_err(|err| format!("Failed to read config file '{}': {}", filename, err))?;

    parse_config_text(&text)
        .map_err(|err| format!("Could not parse YAML file '{}': {}", filename, err))
}

fn parse_config_text(text: &str) -> Result<Config, String> {
    let mut root: Value =
        serde_yaml::from_str(text).map_err(|err| format!("failed to parse YAML: {}", err))?;
    let config_version = extract_config_version(&root)?;
    ensure_supported_version(config_version)?;
    root = migrate_to_current_version(root, config_version)?;
    apply_global_lb_fallback(&mut root);
    let worker_threads_explicit = root
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String("performance".to_string())))
        .and_then(Value::as_mapping)
        .is_some_and(|performance| {
            performance.contains_key(Value::String("worker_threads".to_string()))
        });
    let mut config: Config = serde_yaml::from_value(root)
        .map_err(|err| format!("failed to deserialize config structure: {}", err))?;
    config.performance.worker_threads_explicit = worker_threads_explicit;
    Ok(config)
}

fn extract_config_version(root: &Value) -> Result<u32, String> {
    let Some(root_map) = root.as_mapping() else {
        return Err("config root must be a YAML mapping/object".to_string());
    };

    let version_key = Value::String("version".to_string());
    let Some(version_value) = root_map.get(&version_key) else {
        return Ok(CURRENT_CONFIG_VERSION);
    };

    let raw = version_value
        .as_u64()
        .ok_or_else(|| "config 'version' must be a positive integer".to_string())?;

    u32::try_from(raw).map_err(|_| format!("config 'version' value {} is out of range", raw))
}

fn ensure_supported_version(version: u32) -> Result<(), String> {
    if SUPPORTED_CONFIG_VERSIONS.contains(&version) {
        return Ok(());
    }

    let supported = SUPPORTED_CONFIG_VERSIONS
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "unsupported config version '{}'; supported versions: [{}]",
        version, supported
    ))
}

fn migrate_to_current_version(root: Value, from_version: u32) -> Result<Value, String> {
    match from_version {
        CURRENT_CONFIG_VERSION => Ok(root),
        _ => Err(format!(
            "config version '{}' cannot be migrated to current version '{}'",
            from_version, CURRENT_CONFIG_VERSION
        )),
    }
}

fn apply_global_lb_fallback(root: &mut Value) {
    let Some(root_map) = root.as_mapping_mut() else {
        return;
    };

    let lb_key = Value::String("load_balancing".to_string());
    let upstream_key = Value::String("upstream".to_string());

    let Some(global_lb) = root_map.get(&lb_key).cloned() else {
        return;
    };
    let Some(upstreams) = root_map
        .get_mut(&upstream_key)
        .and_then(Value::as_mapping_mut)
    else {
        return;
    };

    for upstream_value in upstreams.values_mut() {
        let Some(upstream_map) = upstream_value.as_mapping_mut() else {
            continue;
        };
        ensure_mapping_has_lb(upstream_map, &lb_key, global_lb.clone());
    }
}

fn ensure_mapping_has_lb(map: &mut Mapping, lb_key: &Value, global_lb: Value) {
    if !map.contains_key(lb_key) {
        map.insert(lb_key.clone(), global_lb);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{MAX_CONFIG_FILE_BYTES, parse_config_text, read_config};

    #[test]
    fn applies_global_lb_to_upstream_without_override() {
        let yaml = r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "certs/cert.pem"
    key: "certs/key.pem"
load_balancing:
  type: consistent-hash
upstream:
  inherited:
    route:
      path_prefix: "/"
    backends:
      - id: b1
        address: "http://127.0.0.1:7001"
        weight: 1
        health_check: {}
  explicit:
    load_balancing:
      type: random
    route:
      path_prefix: "/api"
    backends:
      - id: b2
        address: "http://127.0.0.1:7002"
        weight: 1
        health_check: {}
"#;

        let cfg = parse_config_text(yaml).expect("config should parse");
        assert_eq!(
            cfg.upstream
                .get("inherited")
                .map(|u| u.load_balancing.lb_type.as_str()),
            Some("consistent-hash")
        );
        assert_eq!(
            cfg.upstream
                .get("explicit")
                .map(|u| u.load_balancing.lb_type.as_str()),
            Some("random")
        );
    }

    #[test]
    fn rejects_unsupported_config_version() {
        let yaml = r#"
version: 2
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "certs/cert.pem"
    key: "certs/key.pem"
upstream:
  default:
    route:
      path_prefix: "/"
    backends:
      - id: b1
        address: "http://127.0.0.1:7001"
        weight: 1
        health_check: {}
"#;

        let err = parse_config_text(yaml).expect_err("version 2 should be rejected");
        assert!(err.contains("unsupported config version"));
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let yaml = r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "certs/cert.pem"
    key: "certs/key.pem"
upstream:
  default:
    route:
      path_prefix: "/"
    backends:
      - id: b1
        address: "http://127.0.0.1:7001"
        weight: 1
        health_check: {}
unknown_root: true
"#;

        let err = parse_config_text(yaml).expect_err("unknown_root should be rejected");
        assert!(err.contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_nested_field() {
        let yaml = r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "certs/cert.pem"
    key: "certs/key.pem"
upstream:
  default:
    route:
      path_prefix: "/"
    backends:
      - id: b1
        address: "http://127.0.0.1:7001"
        weight: 1
        health_check: {}
performance:
  worker_threads: 1
  typo_field: 10
"#;

        let err = parse_config_text(yaml).expect_err("typo_field should be rejected");
        assert!(err.contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_control_api_nested_field() {
        let yaml = r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "certs/cert.pem"
    key: "certs/key.pem"
upstream:
  default:
    route:
      path_prefix: "/"
    backends:
      - id: b1
        address: "http://127.0.0.1:7001"
        weight: 1
        health_check: {}
observability:
  control_api:
    enabled: true
    address: "127.0.0.1"
    port: 9902
    health_path: "/health"
    ready_path: "/ready"
    runtime_path: "/admin/runtime"
    restart_path: "/admin/runtime/restart"
    auth_token: "token"
    unknown_control_field: true
"#;

        let err = parse_config_text(yaml).expect_err("unknown_control_field should be rejected");
        assert!(err.contains("unknown field"));
    }

    #[test]
    fn read_config_rejects_oversized_yaml_before_parse() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("oversized.yaml");
        fs::write(&path, vec![b'x'; (MAX_CONFIG_FILE_BYTES as usize) + 1]).expect("write");

        let err = read_config(path.to_string_lossy().as_ref()).expect_err("oversized config");

        assert!(err.contains("exceeds maximum supported size"));
    }

    #[test]
    fn read_config_accepts_normal_sized_valid_yaml() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        let yaml = r#"
version: 1
listen:
  protocol: http3
  address: "127.0.0.1"
  port: 9889
  tls:
    cert: "certs/cert.pem"
    key: "certs/key.pem"
upstream:
  default:
    route:
      path_prefix: "/"
    backends:
      - id: b1
        address: "http://127.0.0.1:7001"
        weight: 1
        health_check: {}
"#;
        fs::write(&path, yaml).expect("write");

        let cfg = read_config(path.to_string_lossy().as_ref()).expect("valid config file");

        assert_eq!(cfg.version, 1);
        assert!(cfg.upstream.contains_key("default"));
    }
}
