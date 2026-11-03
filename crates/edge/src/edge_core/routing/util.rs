use std::borrow::Cow;

#[inline(always)]
pub fn prefix_boundary_matches(path: &str, prefix_len: usize) -> bool {
    if prefix_len <= 1 {
        return true;
    }
    if path.len() == prefix_len {
        return true;
    }
    path.as_bytes().get(prefix_len) == Some(&b'/')
}

/// Return the URI path component from a request-target or HTTP/3 `:path`.
///
/// Routing must ignore the query component, while the original request-target
/// is retained elsewhere for forwarding to the upstream.
#[inline]
pub fn uri_path(path_and_query: &str) -> &str {
    path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path)
}

/// Canonicalize percent-encoded unreserved bytes in a URI path for routing.
///
/// The request validator rejects escapes for reserved bytes. Keeping this
/// helper separate lets the routing layer retain the same behavior for direct
/// callers while making `/%61dmin` equivalent to `/admin`.
#[inline]
pub fn canonical_uri_path(path_and_query: &str) -> Cow<'_, str> {
    let path = uri_path(path_and_query);
    let bytes = path.as_bytes();
    let mut canonical = None::<String>;
    let mut copied_until = 0;
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
        {
            let decoded = high << 4 | low;
            if is_uri_unreserved(decoded) {
                let output = canonical.get_or_insert_with(|| String::with_capacity(path.len()));
                output.push_str(&path[copied_until..index]);
                output.push(decoded as char);
                index += 3;
                copied_until = index;
                continue;
            }
        }
        index += 1;
    }

    match canonical {
        Some(mut output) => {
            output.push_str(&path[copied_until..]);
            Cow::Owned(output)
        }
        None => Cow::Borrowed(path),
    }
}

/// Return a canonical request-target with the query preserved verbatim.
pub fn canonical_request_target(path_and_query: &str) -> String {
    let path = canonical_uri_path(path_and_query);
    match path_and_query.split_once('?') {
        Some((_, query)) => format!("{path}?{query}"),
        None => path.into_owned(),
    }
}

#[inline]
fn is_uri_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Returns whether a request path can be interpreted differently by routing
/// and an upstream server.
pub fn request_path_is_ambiguous(path_and_query: &str) -> bool {
    let path = uri_path(path_and_query);
    if path.contains("//") || path.contains('\\') {
        return true;
    }

    // Percent escapes encode octets, not Latin-1 code points. Decode into a
    // byte buffer first so invalid and overlong UTF-8 sequences cannot be
    // reinterpreted differently by a downstream component.
    let mut decoded = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return true;
            }
            let Some(high) = hex_digit(bytes[index + 1]) else {
                return true;
            };
            let Some(low) = hex_digit(bytes[index + 2]) else {
                return true;
            };
            let decoded_byte = high << 4 | low;
            if !is_uri_unreserved(decoded_byte) {
                return true;
            }
            decoded.push(decoded_byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    let Ok(decoded) = std::str::from_utf8(&decoded) else {
        return true;
    };

    decoded
        .split('/')
        .any(|segment| segment == "." || segment == "..")
        || decoded.contains("//")
        || decoded.contains('\\')
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_request_target, canonical_uri_path, prefix_boundary_matches,
        request_path_is_ambiguous, uri_path,
    };

    #[test]
    fn uri_path_strips_query_without_changing_path() {
        assert_eq!(uri_path("/admin"), "/admin");
        assert_eq!(uri_path("/admin?x=1"), "/admin");
        assert_eq!(uri_path("/admin?"), "/admin");
    }

    #[test]
    fn canonical_uri_path_decodes_unreserved_bytes() {
        assert_eq!(canonical_uri_path("/%61dmin/%7Euser"), "/admin/~user");
        assert_eq!(canonical_uri_path("/admin?next=%2F"), "/admin");
        assert_eq!(
            canonical_request_target("/%61dmin?next=%2F"),
            "/admin?next=%2F"
        );
    }

    #[test]
    fn prefix_boundary_matches_exact_prefix_length() {
        assert!(prefix_boundary_matches("/api", "/api".len()));
    }

    #[test]
    fn prefix_boundary_matches_segment_boundary() {
        assert!(prefix_boundary_matches("/api/v1", "/api".len()));
    }

    #[test]
    fn prefix_boundary_rejects_mid_segment_match() {
        assert!(!prefix_boundary_matches("/apixyz", "/api".len()));
    }

    #[test]
    fn prefix_boundary_treats_root_prefix_as_match() {
        assert!(prefix_boundary_matches("/anything", 1));
    }

    #[test]
    fn request_path_rejects_ambiguous_dot_segments_and_slashes() {
        for path in [
            "/public/../admin/x",
            "/%2e%2e/admin/x",
            "/%2E./admin/x",
            "//admin/x",
            "/admin\\x",
            "/public%2f..%2fadmin",
            "/public%5cadmin",
        ] {
            assert!(
                request_path_is_ambiguous(path),
                "path should be rejected: {path}"
            );
        }
    }

    #[test]
    fn request_path_rejects_overlong_and_invalid_utf8_percent_encodings() {
        for path in [
            "/public%c0%afadmin",
            "/public%e0%80%afadmin",
            "/public%f0%80%80%afadmin",
            "/public%c1%9cadmin",
            "/public%afadmin",
            "/public%ffadmin",
        ] {
            assert!(
                request_path_is_ambiguous(path),
                "invalid UTF-8 path encoding should be rejected: {path}"
            );
        }
    }

    #[test]
    fn request_path_rejects_reserved_and_non_ascii_percent_encoding() {
        for path in [
            "/public/report%20final?next=../admin",
            "/caf%C3%A9/menu",
            "/admin%2Fsettings",
            "/admin%252Fsettings",
        ] {
            assert!(
                request_path_is_ambiguous(path),
                "path should be rejected: {path}"
            );
        }
    }

    #[test]
    fn request_path_allows_unreserved_percent_encoding_and_query_values() {
        assert!(!request_path_is_ambiguous("/%61dmin?next=../admin"));
        assert!(!request_path_is_ambiguous("/café/menu"));
    }
}
