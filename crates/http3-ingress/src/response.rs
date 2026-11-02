use quiche::h3::Header;

pub fn response_header_block<'a, I>(status: http::StatusCode, headers: I) -> Vec<Header>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let headers = headers.into_iter();
    let mut response = Vec::with_capacity(headers.size_hint().0 + 1);
    response.push(Header::new(b":status", status.as_str().as_bytes()));
    response.extend(headers.map(|(name, value)| Header::new(name, value)));
    response
}

pub fn response_headers_with_defaults<'a, I>(
    status: http::StatusCode,
    body: &[u8],
    headers: I,
    extra_header: Option<(&'a [u8], &'a [u8])>,
) -> Vec<Header>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let headers = headers.into_iter();
    let mut response =
        Vec::with_capacity(headers.size_hint().0 + usize::from(extra_header.is_some()) + 3);
    response.push(Header::new(b":status", status.as_str().as_bytes()));
    let mut has_content_type = false;
    let mut has_content_length = false;
    for (name, value) in headers.chain(extra_header) {
        has_content_type |=
            name.eq_ignore_ascii_case(http::header::CONTENT_TYPE.as_str().as_bytes());
        has_content_length |=
            name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str().as_bytes());
        response.push(Header::new(name, value));
    }
    if !has_content_type {
        response.push(Header::new(b"content-type", b"text/plain"));
    }
    if !has_content_length {
        response.push(Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ));
    }
    response
}

pub fn send_response_head<'a, I>(
    h3: &mut quiche::h3::Connection,
    quic: &mut quiche::Connection,
    stream_id: u64,
    status: http::StatusCode,
    headers: I,
    end_stream: bool,
) -> Result<(), quiche::h3::Error>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let headers = response_header_block(status, headers);
    h3.send_response(quic, stream_id, &headers, end_stream)
}

pub fn send_response_body(
    h3: &mut quiche::h3::Connection,
    quic: &mut quiche::Connection,
    stream_id: u64,
    body: &[u8],
    end_stream: bool,
) -> Result<usize, quiche::h3::Error> {
    h3.send_body(quic, stream_id, body, end_stream)
}

pub fn send_response_trailers<'a, I>(
    h3: &mut quiche::h3::Connection,
    quic: &mut quiche::Connection,
    stream_id: u64,
    trailers: I,
) -> Result<(), quiche::h3::Error>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let trailers = trailers
        .into_iter()
        .map(|(name, value)| Header::new(name, value))
        .collect::<Vec<_>>();
    h3.send_additional_headers(quic, stream_id, &trailers, false, false)
}

pub fn write_complete_response<'a, I>(
    h3: &mut quiche::h3::Connection,
    quic: &mut quiche::Connection,
    stream_id: u64,
    status: http::StatusCode,
    body: &[u8],
    headers: I,
    extra_header: Option<(&'a [u8], &'a [u8])>,
) -> Result<(), quiche::h3::Error>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let headers = response_headers_with_defaults(status, body, headers, extra_header);
    h3.send_response(quic, stream_id, &headers, false)?;
    h3.send_body(quic, stream_id, body, true)?;
    Ok(())
}

pub fn write_simple_response(
    h3: &mut quiche::h3::Connection,
    quic: &mut quiche::Connection,
    stream_id: u64,
    status: http::StatusCode,
    body: &[u8],
) -> Result<(), quiche::h3::Error> {
    write_complete_response(
        h3,
        quic,
        stream_id,
        status,
        body,
        std::iter::empty::<(&[u8], &[u8])>(),
        None,
    )
}

pub fn write_overload_response(
    h3: &mut quiche::h3::Connection,
    quic: &mut quiche::Connection,
    stream_id: u64,
    body: &[u8],
    retry_after_seconds: u32,
) -> Result<(), quiche::h3::Error> {
    let retry_after = retry_after_seconds.max(1).to_string();
    write_complete_response(
        h3,
        quic,
        stream_id,
        http::StatusCode::SERVICE_UNAVAILABLE,
        body,
        std::iter::empty::<(&[u8], &[u8])>(),
        Some((b"retry-after", retry_after.as_bytes())),
    )
}

pub fn cancel_response_stream(
    quic: &mut quiche::Connection,
    stream_id: u64,
    error_code: u64,
) -> Result<(), quiche::Error> {
    quic.stream_shutdown(stream_id, quiche::Shutdown::Write, error_code)
}
