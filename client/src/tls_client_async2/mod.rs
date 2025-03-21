//! Provides a TLS client which exposes an async socket.
//!
//! This library provides the [bind_client] function which attaches a TLS client to a socket
//! connection and then exposes a [TlsConnection] object, which provides an async socket API for
//! reading and writing cleartext. The TLS client will then automatically encrypt and decrypt
//! traffic and forward that to the provided socket.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod conn;
use std::{
  io::Read,
  pin::Pin,
  task::{Context, Poll},
};

use bytes::{Buf, Bytes};
pub use conn::TlsConnection;
use futures::{
  channel::mpsc, future::Fuse, select_biased, stream::Next, AsyncRead, AsyncReadExt, AsyncWrite,
  AsyncWriteExt, Future, FutureExt, SinkExt, StreamExt,
};
use tls_client2::ClientConnection;
use tracing::{debug, error, trace, warn};

const RX_TLS_BUF_SIZE: usize = 1 << 13; // 8 KiB
const RX_BUF_SIZE: usize = 1 << 13; // 8 KiB

/// An error that can occur during a TLS connection.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
  #[error(transparent)]
  TlsError(#[from] tls_client2::Error),
  #[error(transparent)]
  IOError(#[from] std::io::Error),
}

/// Closed connection data.
#[derive(Debug)]
pub struct ClosedConnection {
  /// The connection for the client
  pub client: ClientConnection,
  /// Sent plaintext bytes
  pub sent:   Vec<u8>,
  /// Received plaintext bytes
  pub recv:   Vec<u8>,
}

/// A result type alias for a closed connection and its associated socket. Primarily returned by
/// `bind_client` to represent the outcome of establishing a client connection.
///
/// This alias represents one of the following outcomes:
/// - A successful [`ClosedConnection`] paired with a socket of type `T`.
/// - A failure encapsulated in a [`ConnectionError`].
pub type MaybeConnectionWithSocket<T> = Result<(ClosedConnection, T), ConnectionError>;

/// A future which runs the TLS connection to completion.
///
/// This future must be polled in order for the connection to make progress.
#[must_use = "futures do nothing unless polled"]
pub struct ConnectionFuture<T> {
  fut: Pin<Box<dyn Future<Output = MaybeConnectionWithSocket<T>> + Send>>,
}

impl<T> Future for ConnectionFuture<T> {
  type Output = MaybeConnectionWithSocket<T>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.fut.poll_unpin(cx)
  }
}

/// Binds a client connection to the provided socket.
///
/// Returns a connection handle and a future which runs the connection to completion.
///
/// # Errors
///
/// Any connection errors that occur will be returned from the future, not [`TlsConnection`].
pub fn bind_client<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
  socket: T,
  mut client: ClientConnection,
) -> (TlsConnection, ConnectionFuture<T>) {
  let (tx_sender, mut tx_receiver) = mpsc::channel(1 << 14);
  let (mut rx_sender, rx_receiver) = mpsc::channel(1 << 14);

  let conn = TlsConnection::new(tx_sender, rx_receiver);

  let fut = async move {
    client.start().await?;
    let mut notify = client.get_notify().await?;

    let (mut server_rx, mut server_tx) = socket.split();

    let mut rx_tls_buf = [0u8; RX_TLS_BUF_SIZE];
    let mut rx_buf = [0u8; RX_BUF_SIZE];

    let mut handshake_done = false;
    let mut client_closed = false;
    let mut server_closed = false;

    let mut sent = Vec::with_capacity(1024);
    let mut recv = Vec::with_capacity(1024);

    let mut rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
    // We don't start writing application data until the handshake is complete.
    let mut tx_recv_fut: Fuse<Next<'_, mpsc::Receiver<Bytes>>> = Fuse::terminated();

    // Runs both the tx and rx halves of the connection to completion.
    // This loop does not terminate until the *SERVER* closes the connection and
    // we've processed all received data. If an error occurs, the `TlsConnection`
    // channels will be closed and the error will be returned from this future.
    'conn: loop {
      // Write all pending TLS data to the server.
      if client.wants_write() && !client_closed {
        trace!("client wants to write");
        while client.wants_write() {
          let _sent = client.write_tls_async(&mut server_tx).await?;
          trace!("sent {} tls bytes to server", _sent);
        }
        server_tx.flush().await?;
      }

      // Forward received plaintext to `TlsConnection`.
      while !client.plaintext_is_empty() {
        let read = client.read_plaintext(&mut rx_buf)?;
        recv.extend(&rx_buf[..read]);
        // Ignore if the receiver has hung up.
        _ = rx_sender.send(Ok(Bytes::copy_from_slice(&rx_buf[..read]))).await;
        trace!("forwarded {} plaintext bytes to conn", read);
      }

      if !client.is_handshaking() && !handshake_done {
        debug!("handshake complete");
        handshake_done = true;
        // Start reading application data that needs to be transmitted from the `TlsConnection`.
        tx_recv_fut = tx_receiver.next().fuse();
      }

      if server_closed && client.plaintext_is_empty() && client.buffer_len().await? == 0 {
        break 'conn;
      }

      select_biased! {
          // Reads TLS data from the server and writes it into the client.
          received = &mut rx_tls_fut => {
              let received = received?;
              trace!("received {} tls bytes from server", received);

              // Loop until we've processed all the data we received in this read.
              // Note that we must make one iteration even if `received == 0`.
              let mut processed = 0;

              // Check for a special termination character. We do not need to place
              // it back on the buffer because we recreate the reader below.
              let mut reader = rx_tls_buf[..received].reader();
              let mut bytes_buf = [0u8; 1];
              reader.read_exact(&mut bytes_buf)?;
              let is_terminate_byte = received == 1 && bytes_buf.first().cloned() == Some(255);

              let mut reader = rx_tls_buf[..received].reader();
              loop {
                  processed += client.read_tls(&mut reader)?;
                  client.process_new_packets().await?;

                  debug_assert!(processed <= received);
                  if processed >= received {
                      break;
                  }
              }

              trace!("processed {} tls bytes from server", processed);

              // Check: EOF or server properly closed or proxy closed
              if received == 0 || client.received_close_notify() || is_terminate_byte {
                  trace!("connection closed: eof or server closed or proxy terminate");
                  server_closed = true;
                  client.server_closed().await?;

                  // Do not read from the socket again.
                  rx_tls_fut = Fuse::terminated();
              } else {
                  // Reset the read future so next iteration we can read again.
                  trace!("ready to read more data....");
                  rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
              }
          }

          // If we receive None from `TlsConnection`, it has closed, so we
          // send a close_notify to the server.
          data = &mut tx_recv_fut => {
              if let Some(data) = data {
                  debug!("writing {} plaintext bytes to client", data.len());

                  sent.extend(&data);
                  client
                      .write_all_plaintext(&data)
                      .await?;

                  tx_recv_fut = tx_receiver.next().fuse();
              } else {
                  if !server_closed {
                      if let Err(e) = send_close_notify(&mut client, &mut server_tx).await {
                          warn!("failed to send close_notify to server: {}", e);
                      }
                  }

                  trace!("closing client and terminating receiving end.");
                  client_closed = true;
                  tx_recv_fut = Fuse::terminated();
              }
          }
          // Waits for a notification from the backend that it is ready to decrypt data.
          _ = &mut notify => {
              trace!("backend is ready to decrypt");

              client.process_new_packets().await?;
          }
      }
    }
    trace!("client shutdown");

    // _ = server_tx.close().await; // MATT: socket can't be closed if we still need it

    tx_receiver.close();
    rx_sender.close_channel();

    let reunited_socket = server_rx.reunite(server_tx).unwrap();

    debug!(
      "server close notify: {}, sent: {}, recv: {}",
      client.received_close_notify(),
      sent.len(),
      recv.len()
    );

    Ok((ClosedConnection { client, sent, recv }, reunited_socket))
  };

  #[cfg(feature = "tracing")]
  let fut = fut.instrument(debug_span!("tls_connection"));

  let fut = ConnectionFuture { fut: Box::pin(fut) };

  (conn, fut)
}

async fn send_close_notify(
  client: &mut ClientConnection,
  server_tx: &mut (impl AsyncWrite + Unpin),
) -> Result<(), ConnectionError> {
  trace!("sending close_notify to server");
  client.send_close_notify().await?;

  // Flush all remaining plaintext
  while client.wants_write() {
    client.write_tls_async(server_tx).await?;
  }
  server_tx.flush().await?;

  Ok(())
}
