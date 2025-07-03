use crate::keys;
use crate::ssl;
use crate::utils;
use anyhow::{self, Context};
use futures;
use hyper::rt::{Read, ReadBufCursor, Write};
use primitive_types::U256;
use rustls::pki_types::ServerName;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use tokio::{
    io::AsyncRead, io::AsyncWrite, io::ReadBuf, net::TcpListener, net::TcpStream,
    net::ToSocketAddrs,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use tonic::transport::{Channel, Uri, server::Connected};
use tower;
use x509_parser;

#[cfg(test)]
use futures::future;

#[cfg(test)]
use tokio::io::DuplexStream;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    peer_certificate: rustls::pki_types::CertificateDer<'static>,
    peer_public_key: U256,
}

impl ConnectionInfo {
    fn new(
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> anyhow::Result<ConnectionInfo> {
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

pub struct TlsServerStreamAdapter<IO: AsyncRead + AsyncWrite + Unpin> {
    info: ConnectionInfo,
    inner: server::TlsStream<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsServerStreamAdapter<IO> {
    pub fn new(
        inner_stream: server::TlsStream<IO>,
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            info: ConnectionInfo::new(peer_certificate)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))?,
            inner: inner_stream,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsServerStreamAdapter<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsServerStreamAdapter<IO> {
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

impl<IO: AsyncRead + AsyncWrite + Unpin> Connected for TlsServerStreamAdapter<IO> {
    type ConnectInfo = ConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

pub struct TlsClientStreamAdapter<IO: AsyncRead + AsyncWrite + Unpin> {
    info: ConnectionInfo,
    inner: client::TlsStream<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> TlsClientStreamAdapter<IO> {
    pub fn new(
        inner_stream: client::TlsStream<IO>,
        peer_certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            info: ConnectionInfo::new(peer_certificate)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))?,
            inner: inner_stream,
        })
    }

    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Read for TlsClientStreamAdapter<IO> {
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

impl<IO: AsyncRead + AsyncWrite + Unpin> Write for TlsClientStreamAdapter<IO> {
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
) -> std::io::Result<rustls::pki_types::CertificateDer<'static>> {
    let certificates = connection
        .peer_certificates()
        .context("certificate missing")
        .map_err(|error| Error::new(ErrorKind::PermissionDenied, error))?;
    if certificates.len() != 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unexpected number of mTLS certificates (expected: 1, got {})",
                certificates.len()
            ),
        ));
    }
    Ok(certificates[0].clone())
}

pub trait Listener<IO: AsyncRead + AsyncWrite + Unpin>: Send + Sync {
    fn accept<'a>(&'a self) -> Pin<Box<dyn Future<Output = std::io::Result<IO>> + Send + 'a>>;
}

pub struct TcpListenerAdapter {
    inner: TcpListener,
}

impl TcpListenerAdapter {
    pub async fn new<A: ToSocketAddrs>(address: A) -> std::io::Result<Self> {
        let inner = TcpListener::bind(address).await?;
        Ok(Self { inner })
    }

    pub fn local_address(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }
}

impl Listener<TcpStream> for TcpListenerAdapter {
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + 'a>> {
        Box::pin(async move {
            let (stream, _) = self.inner.accept().await?;
            Ok(stream)
        })
    }
}

#[cfg(test)]
pub struct MockListener {
    stream: Mutex<Option<DuplexStream>>,
}

#[cfg(test)]
impl MockListener {
    pub fn new(stream: DuplexStream) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
        }
    }
}

#[cfg(test)]
impl Listener<DuplexStream> for MockListener {
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<DuplexStream>> + Send + 'a>> {
        let mut lock = self.stream.lock().unwrap();
        Box::pin(match lock.take() {
            Some(stream) => future::Either::Left(future::ready(Ok(stream))),
            None => future::Either::Right(future::pending()),
        })
    }
}

type TlsHandshakeFuture<IO> =
    Pin<Box<dyn Future<Output = std::io::Result<TlsServerStreamAdapter<IO>>> + Send>>;

pub struct IncomingWithMTls<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    listener: Arc<dyn Listener<IO>>,
    acceptor: TlsAcceptor,
    pending: TlsHandshakeFuture<IO>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> IncomingWithMTls<IO> {
    fn accept(listener: Arc<dyn Listener<IO>>, acceptor: TlsAcceptor) -> TlsHandshakeFuture<IO> {
        Box::pin(async move {
            let stream = listener.accept().await?;
            let stream = acceptor.accept(stream).await?;
            let (_, connection) = stream.get_ref();
            let certificate = get_peer_certificate(connection)?;
            TlsServerStreamAdapter::new(stream, certificate)
        })
    }

    pub async fn new(
        listener: Arc<dyn Listener<IO>>,
        key_manager: Arc<keys::KeyManager>,
        certificate: Arc<rcgen::Certificate>,
    ) -> anyhow::Result<Self> {
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
                )?,
        ));
        let pending = Self::accept(listener.clone(), acceptor.clone());
        Ok(Self {
            listener,
            acceptor,
            pending,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> futures::Stream for IncomingWithMTls<IO> {
    type Item = std::io::Result<TlsServerStreamAdapter<IO>>;

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

pub trait Connector<IO: AsyncRead + AsyncWrite>: Send + Sync {
    fn connect<'a>(
        &'a self,
        address: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<IO>> + Send + 'a>>;
}

pub struct TcpConnectorAdapter {}

impl TcpConnectorAdapter {
    pub fn new() -> Self {
        Self {}
    }
}

impl Connector<TcpStream> for TcpConnectorAdapter {
    fn connect<'a>(
        &'a self,
        address: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + 'a>> {
        Box::pin(async move {
            let stream = TcpStream::connect(address).await?;
            Ok(stream)
        })
    }
}

#[cfg(test)]
pub struct MockConnector {
    stream: Mutex<Option<DuplexStream>>,
}

#[cfg(test)]
impl MockConnector {
    pub fn new(stream: DuplexStream) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
        }
    }
}

#[cfg(test)]
impl Connector<DuplexStream> for MockConnector {
    fn connect<'a>(
        &'a self,
        _address: String,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<DuplexStream>> + Send + 'a>> {
        let mut lock = self.stream.lock().unwrap();
        Box::pin(match lock.take() {
            Some(stream) => future::Either::Left(future::ready(Ok(stream))),
            None => future::Either::Right(future::pending()),
        })
    }
}

struct ConnectorWithMTls<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    tcp_connector: Arc<dyn Connector<IO>>,
    tls_connector: TlsConnector,
    peer_certificate: Arc<Mutex<Option<rustls::pki_types::CertificateDer<'static>>>>,
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> ConnectorWithMTls<IO> {
    const DEFAULT_PORT: u16 = 443;

    pub fn new(
        tcp_connector: Arc<dyn Connector<IO>>,
        key_manager: Arc<keys::KeyManager>,
        certificate: Arc<rcgen::Certificate>,
        peer_certificate: Arc<Mutex<Option<rustls::pki_types::CertificateDer<'static>>>>,
    ) -> anyhow::Result<ConnectorWithMTls<IO>> {
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(
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
        {
            let mut guard = peer_certificate.lock().unwrap();
            *guard = None;
        }
        Ok(Self {
            tcp_connector,
            tls_connector,
            peer_certificate,
        })
    }
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> tower::Service<Uri>
    for ConnectorWithMTls<IO>
{
    type Response = TlsClientStreamAdapter<IO>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _context: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Uri) -> Self::Future {
        let tcp_connector = self.tcp_connector.clone();
        let tls_connector = self.tls_connector.clone();
        let peer_certificate = self.peer_certificate.clone();
        Box::pin(async move {
            let host = request
                .host()
                .context("invalid host name")
                .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
            let port = request.port_u16().unwrap_or(Self::DEFAULT_PORT);

            let server_name = ServerName::try_from(host.to_owned())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid server name"))?;

            let address = format!("{}:{}", host, port);
            let stream = tcp_connector.connect(address).await?;
            let stream = tls_connector.connect(server_name, stream).await?;
            let (_, connection) = stream.get_ref();
            let certificate = get_peer_certificate(connection)?;
            {
                let mut guard = peer_certificate.lock().unwrap();
                *guard = Some(certificate.clone());
            }
            Ok(TlsClientStreamAdapter::new(stream, certificate)?)
        })
    }
}

pub async fn connect_with_mtls(
    key_manager: Arc<keys::KeyManager>,
    certificate: Arc<rcgen::Certificate>,
    uri: Uri,
) -> anyhow::Result<(Channel, ConnectionInfo)> {
    let peer_certificate = Arc::new(Mutex::new(
        None::<rustls::pki_types::CertificateDer<'static>>,
    ));
    let channel = Channel::builder(uri)
        .connect_with_connector(
            ConnectorWithMTls::new(
                Arc::new(TcpConnectorAdapter::new()),
                key_manager.clone(),
                certificate.clone(),
                peer_certificate.clone(),
            )
            .unwrap(),
        )
        .await?;
    let peer_certificate = peer_certificate.lock().unwrap().as_mut().unwrap().clone();
    let connection_info = ConnectionInfo::new(peer_certificate)?;
    Ok((channel, connection_info))
}

#[cfg(test)]
pub async fn mock_connect_with_mtls(
    stream: DuplexStream,
    key_manager: Arc<keys::KeyManager>,
    certificate: Arc<rcgen::Certificate>,
) -> anyhow::Result<(Channel, ConnectionInfo)> {
    let peer_certificate = Arc::new(Mutex::new(
        None::<rustls::pki_types::CertificateDer<'static>>,
    ));
    let channel = Channel::builder("http://fake".parse().unwrap())
        .connect_with_connector(
            ConnectorWithMTls::new(
                Arc::new(MockConnector::new(stream)),
                key_manager.clone(),
                certificate.clone(),
                peer_certificate.clone(),
            )
            .unwrap(),
        )
        .await?;
    let peer_certificate = peer_certificate.lock().unwrap().as_mut().unwrap().clone();
    let connection_info = ConnectionInfo::new(peer_certificate)?;
    Ok((channel, connection_info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dotakon::{
        self, node_service_v1_client::NodeServiceV1Client,
        node_service_v1_server::NodeServiceV1Server,
    };
    use crate::fake::FakeNodeService;
    use crate::utils::public_key_to_wallet_address;
    use tokio::{self, sync::Notify};
    use tonic::{Request, transport::Server};

    #[tokio::test]
    async fn test_tcp_connection() {
        let nonce = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, server_public_key, _) = utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key));
        let server_certificate = Arc::new(
            ssl::generate_certificate(server_key_manager.clone(), "server".to_string(), nonce)
                .unwrap(),
        );

        let (client_secret_key, client_public_key, _) = utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key));
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
                    public_key_to_wallet_address(client_public_key),
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

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server = tokio::task::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, server_key_manager, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            future.await.unwrap();
        });
        start_client.notified().await;

        let (channel, connection_info) = connect_with_mtls(
            client_key_manager,
            client_certificate,
            format!(
                "http://localhost:{}",
                listener.local_address().unwrap().port()
            )
            .parse()
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(server_public_key, connection_info.peer_public_key());
        assert_eq!(
            utils::public_key_to_wallet_address(server_public_key),
            connection_info.peer_wallet_address()
        );

        let mut client = NodeServiceV1Client::new(channel);
        client
            .get_identity(dotakon::GetIdentityRequest::default())
            .await
            .unwrap();

        server.abort();
        assert!(*(client_checked.lock().unwrap()));
    }

    fn generate_invalid_certificate(
        key_manager: &Arc<keys::KeyManager>,
        canonical_address: &str,
    ) -> anyhow::Result<rcgen::Certificate> {
        let params = rcgen::CertificateParams::new(vec![canonical_address.to_string()])?;
        let key_pair = rcgen::KeyPair::from_remote(Box::new(keys::RemoteEd25519KeyPair::from(
            key_manager.clone(),
        )))?;
        Ok(params.self_signed(&key_pair)?)
    }

    #[tokio::test]
    async fn test_invalid_server_certificate() {
        let nonce = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, _, _) = utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key));
        let server_certificate =
            Arc::new(generate_invalid_certificate(&server_key_manager, "server").unwrap());

        let (client_secret_key, _, _) = utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key));
        let client_certificate = Arc::new(
            ssl::generate_certificate(client_key_manager.clone(), "client".to_string(), nonce)
                .unwrap(),
        );

        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert!(request.extensions().get::<ConnectionInfo>().is_none());
                Ok(request)
            },
        );

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server = tokio::task::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, server_key_manager, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            let _ = future.await;
        });
        start_client.notified().await;

        assert!(
            connect_with_mtls(
                client_key_manager,
                client_certificate,
                format!(
                    "http://localhost:{}",
                    listener.local_address().unwrap().port()
                )
                .parse()
                .unwrap(),
            )
            .await
            .is_err()
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_invalid_client_certificate() {
        let nonce = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, server_public_key, _) = utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key));
        let server_certificate = Arc::new(
            ssl::generate_certificate(server_key_manager.clone(), "server".to_string(), nonce)
                .unwrap(),
        );

        let (client_secret_key, _, _) = utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key));
        let client_certificate =
            Arc::new(generate_invalid_certificate(&client_key_manager, "client").unwrap());

        let service = NodeServiceV1Server::with_interceptor(
            FakeNodeService {},
            move |request: Request<()>| {
                assert!(request.extensions().get::<ConnectionInfo>().is_none());
                Ok(request)
            },
        );

        let listener = Arc::new(TcpListenerAdapter::new("localhost:0").await.unwrap());
        let server_listener = listener.clone();

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server = tokio::task::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(server_listener, server_key_manager, server_certificate)
                    .await
                    .unwrap(),
            );
            server_ready.notify_one();
            let _ = future.await;
        });
        start_client.notified().await;

        assert!(
            async {
                let (channel, connection_info) = connect_with_mtls(
                    client_key_manager,
                    client_certificate,
                    format!(
                        "http://localhost:{}",
                        listener.local_address().unwrap().port()
                    )
                    .parse()
                    .unwrap(),
                )
                .await?;
                assert_eq!(server_public_key, connection_info.peer_public_key());
                assert_eq!(
                    utils::public_key_to_wallet_address(server_public_key),
                    connection_info.peer_wallet_address()
                );
                let mut client = NodeServiceV1Client::new(channel);
                client
                    .get_identity(dotakon::GetIdentityRequest::default())
                    .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await
            .is_err()
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_mock_connection() {
        let nonce = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, server_public_key, _) = utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key));
        let server_certificate = Arc::new(
            ssl::generate_certificate(server_key_manager.clone(), "server".to_string(), nonce)
                .unwrap(),
        );

        let (client_secret_key, client_public_key, _) = utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key));
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
                    public_key_to_wallet_address(client_public_key),
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

        let (server_stream, client_stream) = tokio::io::duplex(4096);

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server = tokio::task::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                IncomingWithMTls::new(
                    Arc::new(MockListener::new(server_stream)),
                    server_key_manager,
                    server_certificate,
                )
                .await
                .unwrap(),
            );
            server_ready.notify_one();
            future.await.unwrap();
        });
        start_client.notified().await;

        let (channel, connection_info) =
            mock_connect_with_mtls(client_stream, client_key_manager, client_certificate)
                .await
                .unwrap();
        assert_eq!(server_public_key, connection_info.peer_public_key());
        assert_eq!(
            utils::public_key_to_wallet_address(server_public_key),
            connection_info.peer_wallet_address()
        );

        let mut client = NodeServiceV1Client::new(channel);
        client
            .get_identity(dotakon::GetIdentityRequest::default())
            .await
            .unwrap();

        server.abort();
        assert!(*(client_checked.lock().unwrap()));
    }
}
