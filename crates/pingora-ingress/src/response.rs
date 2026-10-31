use bytes::Bytes;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

pub fn build_response_header(
    status: http::StatusCode,
    headers: &http::HeaderMap,
) -> Result<ResponseHeader> {
    let mut response = ResponseHeader::build(status, Some(headers.len()))?;
    for (name, value) in headers {
        response.append_header(name.clone(), value.clone())?;
    }
    Ok(response)
}

pub fn apply_normalized_response_headers(
    target: &mut ResponseHeader,
    headers: &http::HeaderMap,
) -> Result<()> {
    let existing_headers = target.headers.keys().cloned().collect::<Vec<_>>();
    for name in existing_headers {
        target.remove_header(&name);
    }
    for (name, value) in headers {
        target.append_header(name.clone(), value.clone())?;
    }
    Ok(())
}

pub async fn write_downstream_response(
    session: &mut Session,
    status: http::StatusCode,
    headers: &[(String, String)],
    body: &[u8],
    extra_header: Option<(&str, &str)>,
) -> Result<()> {
    let mut response = ResponseHeader::build(status, Some(headers.len() + 3))?;
    let mut has_content_type = false;
    let mut has_content_length = false;
    for (name, value) in headers {
        let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) else {
            continue;
        };
        has_content_type |= name == http::header::CONTENT_TYPE;
        has_content_length |= name == http::header::CONTENT_LENGTH;
        response.append_header(name, value)?;
    }
    if let Some((name, value)) = extra_header {
        response.append_header(name, value)?;
    }
    if !has_content_type {
        response.insert_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain"),
        )?;
    }
    if !has_content_length {
        response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
    }
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(body)), true)
        .await
}

pub async fn write_local_response(
    session: &mut Session,
    status: http::StatusCode,
    body: &'static [u8],
    www_authenticate: Option<&'static str>,
    retry_after_seconds: Option<u32>,
) -> Result<()> {
    let mut response = ResponseHeader::build(status, Some(3))?;
    response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
    if let Some(challenge) = www_authenticate {
        response.insert_header(http::header::WWW_AUTHENTICATE, challenge)?;
    }
    if let Some(seconds) = retry_after_seconds {
        response.insert_header(http::header::RETRY_AFTER, seconds.to_string())?;
    }
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from_static(body)), true)
        .await
}

pub async fn write_error_response(
    session: &mut Session,
    status: http::StatusCode,
    body: Bytes,
) -> Result<()> {
    session.respond_error_with_body(status.as_u16(), body).await
}
