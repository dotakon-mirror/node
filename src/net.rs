use crate::keys;
use crate::ssl;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use futures;
use hyper::rt::{Read, ReadBufCursor, Write};
use primitive_types::U256;
use rustls::pki_types::ServerName;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::{
    io::AsyncRead, io::AsyncWrite, io::ReadBuf, net::TcpListener, net::TcpStream,
    net::ToSocketAddrs,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use tonic::transport::{Uri, server::Connected};
use tower;
use x509_parser;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    peer_certificate: rustls::pki_types::CertificateDer<'static>,
    peer_public_key: U256,
}

impl ConnectionInfo {
    fn new(peer_certificate: rustls::pki_types::CertificateDer<'static>) -> Result<ConnectionInfo> {
        let (_, parsed_certificate) =
            x509_parser::parse_x509_certificate(peer_certificate.as_ref())?;
        let peer_public_key = ssl::recover_pallas_public_key(&parsed_certificate)?;
        Ok(Self {
            peer_certificate,
            peer_public_key,
        })
    }

    pub fn peer_certificate(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.peer_certificate.clone()
    }

    pub fn peer_public_key(&self) -> U256 {
        self.peer_public_key
    }

    pub fn peer_wallet_address(&self) -> U256 {
        utils::public_key_to_wallet_address(self.peer_public_key)
    }
}

type TlsServerStream = server::TlsStream<TcpStream>;
type TlsClientStream = client::TlsStream<TcpStream>;

pub struct TlsServerStreamAdapter {
    info: ConnectionInfo,
    inner: TlsServerStream,
}

impl TlsServerStreamAdapter {
    pub fn new(
        inner_stream: TlsServerStream,
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> Result<Self> {
        Ok(Self {
            info: ConnectionInfo::new(peer_certificate)?,
            inner: inner_stream,
        })
    }
}

impl AsyncRead for TlsServerStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for TlsServerStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Connected for TlsServerStreamAdapter {
    type ConnectInfo = ConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

pub struct TlsClientStreamAdapter {
    info: ConnectionInfo,
    inner: TlsClientStream,
}

impl TlsClientStreamAdapter {
    pub fn new(
        inner_stream: TlsClientStream,
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> Result<Self> {
        Ok(Self {
            info: ConnectionInfo::new(peer_certificate)?,
            inner: inner_stream,
        })
    }
}

impl Read for TlsClientStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        mut buffer_cursor: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut raw = Vec::<u8>::new();
        raw.resize(buffer_cursor.remaining(), 0);
        let mut buffer = ReadBuf::new(raw.as_mut_slice());
        let poll = Pin::new(&mut self.inner).poll_read(context, &mut buffer);
        if let Poll::Ready(Ok(())) = &poll {
            buffer_cursor.put_slice(buffer.filled());
        }
        poll
    }
}

impl Write for TlsClientStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn get_peer_certificate(
    connection: &rustls::CommonState,
) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let certificates = connection
        .peer_certificates()
        .context("certificate missing")?;
    if certificates.len() != 1 {
        return Err(anyhow!(
            "unexpected number of mTLS certificates (expected: 1, got {})",
            certificates.len()
        ));
    }
    Ok(certificates[0].clone())
}

type TlsHandshakeFuture =
    Pin<Box<dyn Future<Output = std::io::Result<TlsServerStreamAdapter>> + Send>>;

pub struct IncomingWithMTls {
    listener: Arc<TcpListener>,
    acceptor: TlsAcceptor,
    pending: TlsHandshakeFuture,
}

impl IncomingWithMTls {
    fn accept(listener: Arc<TcpListener>, acceptor: TlsAcceptor) -> TlsHandshakeFuture {
        Box::pin(async move {
            let (stream, _) = listener.accept().await?;
            let stream = acceptor.accept(stream).await?;
            let (_, connection) = stream.get_ref();
            let certificate = get_peer_certificate(connection).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, error)
            })?;
            TlsServerStreamAdapter::new(stream, certificate)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })
    }

    pub async fn new<A: ToSocketAddrs>(
        local_address: A,
        key_manager: Arc<keys::KeyManager>,
        certificate: Arc<rcgen::Certificate>,
    ) -> std::io::Result<Self> {
        let listener = Arc::new(TcpListener::bind(local_address).await?);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(ssl::DotakonClientCertVerifier::new()))
                .with_single_cert(
                    vec![certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            key_manager.export_private_key().unwrap(),
                        ),
                    ),
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?,
        ));
        let pending = Self::accept(listener.clone(), acceptor.clone());
        Ok(Self {
            listener,
            acceptor,
            pending,
        })
    }
}

impl futures::Stream for IncomingWithMTls {
    type Item = std::io::Result<TlsServerStreamAdapter>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.pending.as_mut().poll(context) {
            Poll::Ready(result) => {
                self.pending = Self::accept(self.listener.clone(), self.acceptor.clone());
                Poll::Ready(Some(result))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct ConnectorWithMTls {
    connector: TlsConnector,
}

impl ConnectorWithMTls {
    const DEFAULT_PORT: u16 = 443;

    pub fn new(
        key_manager: Arc<keys::KeyManager>,
        certificate: Arc<rcgen::Certificate>,
    ) -> Result<ConnectorWithMTls> {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ssl::DotakonServerCertVerifier::new()))
                .with_client_auth_cert(
                    vec![certificate.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            key_manager.export_private_key()?,
                        ),
                    ),
                )
                .unwrap(),
        ));
        Ok(Self { connector })
    }
}

impl tower::Service<Uri> for ConnectorWithMTls {
    type Response = TlsClientStreamAdapter;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Uri) -> Self::Future {
        let connector = self.connector.clone();
        Box::pin(async move {
            let host = request
                .host()
                .context("invalid host name")
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            let port = request.port_u16().unwrap_or(Self::DEFAULT_PORT);

            let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;

            let address = format!("{}:{}", host, port);
            let stream = TcpStream::connect(address).await?;
            let stream = connector.connect(server_name, stream).await?;
            let (_, connection) = stream.get_ref();
            let certificate = get_peer_certificate(connection).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, error)
            })?;
            Ok(
                TlsClientStreamAdapter::new(stream, certificate).map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error)
                })?,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dotakon::{
        GetIdentityRequest, node_service_v1_client::NodeServiceV1Client,
        node_service_v1_server::NodeServiceV1Server,
    };
    use crate::fake::FakeNodeService;
    use std::sync::Mutex;
    use tokio::{self, sync::Notify};
    use tonic::{Request, transport::Channel, transport::Server};

    #[tokio::test]
    async fn test_connection() {
        let nonce = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, server_public_key, _, server_wallet_address) =
            utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key).unwrap());
        let server_certificate = Arc::new(
            ssl::generate_certificate(server_key_manager.clone(), "server".to_string(), nonce)
                .unwrap(),
        );

        let (client_secret_key, client_public_key, _, client_wallet_address) =
            utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key).unwrap());
        let client_certificate = Arc::new(
            ssl::generate_certificate(client_key_manager.clone(), "client".to_string(), nonce)
                .unwrap(),
        );

        let client_checked = Arc::new(Mutex::new(false));
        let client_checked_ref = client_checked.clone();
        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert_eq!(
                    client_public_key,
                    request
                        .extensions()
                        .get::<ConnectionInfo>()
                        .unwrap()
                        .peer_public_key()
                );
                assert_eq!(
                    client_wallet_address,
                    request
                        .extensions()
                        .get::<ConnectionInfo>()
                        .unwrap()
                        .peer_wallet_address()
                );
                let mut client_checked = client_checked_ref.lock().unwrap();
                *client_checked = true;
                Ok(request)
            },
        );

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server = tokio::task::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new("localhost:8080", server_key_manager, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            future.await.unwrap();
        });
        start_client.notified().await;

        let channel = Channel::builder("http://localhost:8080".parse().unwrap())
            .connect_with_connector(
                ConnectorWithMTls::new(client_key_manager.clone(), client_certificate.clone())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut client = NodeServiceV1Client::new(channel);
        client
            .get_identity(GetIdentityRequest::default())
            .await
            .unwrap();

        server.abort();
        assert!(*(client_checked.lock().unwrap()));
    }
}
