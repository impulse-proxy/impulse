use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use tokio::sync::mpsc;

/// A streaming HTTP body backed by a tokio mpsc channel.
/// The quiche Data handler sends chunks through the sender;
/// hyper reads them from the receiver as the H2 request body.
pub(crate) struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl ChannelBody {
    pub(crate) fn channel(buffer: usize) -> (mpsc::Sender<Bytes>, Self) {
        let (tx, rx) = mpsc::channel(buffer);
        (tx, Self { rx })
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;
    use http_body_util::BodyExt;
    use hyper::body::Body;

    use super::ChannelBody;

    #[tokio::test]
    async fn channel_body_yields_chunks_in_send_order() {
        let (tx, mut body) = ChannelBody::channel(4);
        tx.send(Bytes::from_static(b"first"))
            .await
            .expect("send first chunk");
        tx.send(Bytes::from_static(b"second"))
            .await
            .expect("send second chunk");
        drop(tx);

        let first = body
            .frame()
            .await
            .expect("first frame should exist")
            .expect("first frame should be ok");
        assert_eq!(
            first.into_data().expect("first data frame"),
            Bytes::from("first")
        );

        let second = body
            .frame()
            .await
            .expect("second frame should exist")
            .expect("second frame should be ok");
        assert_eq!(
            second.into_data().expect("second data frame"),
            Bytes::from("second")
        );
    }

    #[tokio::test]
    async fn dropping_sender_yields_eof() {
        let (tx, mut body) = ChannelBody::channel(1);
        drop(tx);

        assert!(body.frame().await.is_none());
    }

    #[test]
    fn channel_body_error_type_is_infallible() {
        // Compile-time proof that ChannelBody implements the expected Body associated types.
        fn assert_body_error_type<B: Body<Data = Bytes, Error = Infallible>>() {}
        assert_body_error_type::<ChannelBody>();
    }
}
