//! Connection-time configuration selection must leave established connections intact.

use super::*;
use rustls::client::{ClientConfigResolver, ResolvesClientConfig};
use rustls::server::{ResolvesServerConfig, ServerConfigResolver};

#[derive(Debug)]
struct ClientSelection(Arc<Mutex<Arc<ClientConfig>>>);

impl ResolvesClientConfig for ClientSelection {
    fn resolve(&self, _template: &Arc<ClientConfig>) -> Result<Arc<ClientConfig>, Error> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn clone_for_config(&self) -> Arc<dyn ResolvesClientConfig> {
        Arc::new(Self(self.0.clone()))
    }
}

#[derive(Debug)]
struct ServerSelection(Arc<Mutex<Arc<ServerConfig>>>);

impl ResolvesServerConfig for ServerSelection {
    fn resolve(&self, _template: &Arc<ServerConfig>) -> Result<Arc<ServerConfig>, Error> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn clone_for_config(&self) -> Arc<dyn ResolvesServerConfig> {
        Arc::new(Self(self.0.clone()))
    }
}

fn provider_for(suite: SupportedCipherSuite) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        ..provider::default_provider()
    })
}

#[test]
fn client_selection_precedes_the_client_hello_and_retains_established_traffic() {
    let provider = provider::default_provider();
    let client = make_client_config(KeyType::Rsa2048, &provider);
    let server = make_server_config(KeyType::Rsa2048, &provider);
    let first_suite = cipher_suite::TLS13_AES_128_GCM_SHA256;
    let next_suite = cipher_suite::TLS13_AES_256_GCM_SHA384;
    let selected = Arc::new(Mutex::new(Arc::new(
        client
            .clone()
            .with_crypto_provider(provider_for(first_suite))
            .unwrap(),
    )));
    let mut template = client;
    template.handshake_config_resolver = Some(ClientConfigResolver::new(Arc::new(
        ClientSelection(selected.clone()),
    )));
    let template = Arc::new(template);
    let server = Arc::new(server);
    let (mut first_client, mut first_server) = make_pair_for_arc_configs(&template, &server);
    do_handshake(&mut first_client, &mut first_server);
    assert_eq!(first_client.negotiated_cipher_suite(), Some(first_suite));

    let next = selected
        .lock()
        .unwrap()
        .as_ref()
        .clone()
        .with_crypto_provider(provider_for(next_suite))
        .unwrap();
    *selected.lock().unwrap() = Arc::new(next);
    let (mut next_client, mut next_server) = make_pair_for_arc_configs(&template, &server);
    do_handshake(&mut next_client, &mut next_server);
    assert_eq!(next_client.negotiated_cipher_suite(), Some(next_suite));
    assert_eq!(first_client.negotiated_cipher_suite(), Some(first_suite));
    first_client
        .writer()
        .write_all(b"retained")
        .unwrap();
    transfer(&mut first_client, &mut first_server);
    first_server
        .process_new_packets()
        .unwrap();
    let mut received = [0; 8];
    first_server
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"retained");
}

#[test]
fn server_selection_precedes_negotiation_and_retains_established_traffic() {
    let provider = provider::default_provider();
    let client = Arc::new(make_client_config(KeyType::Rsa2048, &provider));
    let server = make_server_config(KeyType::Rsa2048, &provider);
    let first_suite = cipher_suite::TLS13_AES_128_GCM_SHA256;
    let next_suite = cipher_suite::TLS13_AES_256_GCM_SHA384;
    let selected = Arc::new(Mutex::new(Arc::new(
        server
            .clone()
            .with_crypto_provider(provider_for(first_suite))
            .unwrap(),
    )));
    let mut template = server;
    template.handshake_config_resolver = Some(ServerConfigResolver::new(Arc::new(
        ServerSelection(selected.clone()),
    )));
    let template = Arc::new(template);
    let (mut first_client, mut first_server) = make_pair_for_arc_configs(&client, &template);
    do_handshake(&mut first_client, &mut first_server);
    assert_eq!(first_server.negotiated_cipher_suite(), Some(first_suite));

    let next = selected
        .lock()
        .unwrap()
        .as_ref()
        .clone()
        .with_crypto_provider(provider_for(next_suite))
        .unwrap();
    *selected.lock().unwrap() = Arc::new(next);
    let (mut next_client, mut next_server) = make_pair_for_arc_configs(&client, &template);
    do_handshake(&mut next_client, &mut next_server);
    assert_eq!(next_server.negotiated_cipher_suite(), Some(next_suite));
    assert_eq!(first_server.negotiated_cipher_suite(), Some(first_suite));
    first_server
        .writer()
        .write_all(b"retained")
        .unwrap();
    transfer(&mut first_server, &mut first_client);
    first_client
        .process_new_packets()
        .unwrap();
    let mut received = [0; 8];
    first_client
        .reader()
        .read_exact(&mut received)
        .unwrap();
    assert_eq!(&received, b"retained");
}

#[derive(Debug, Default)]
struct CachingClient(Mutex<Option<Arc<ClientConfig>>>);

impl ResolvesClientConfig for CachingClient {
    fn resolve(&self, template: &Arc<ClientConfig>) -> Result<Arc<ClientConfig>, Error> {
        let mut cache = self.0.lock().unwrap();
        if let Some(config) = cache.as_ref() {
            return Ok(config.clone());
        }
        let mut config = template.as_ref().clone();
        config.handshake_config_resolver = None;
        let config = Arc::new(config);
        *cache = Some(config.clone());
        Ok(config)
    }

    fn clone_for_config(&self) -> Arc<dyn ResolvesClientConfig> {
        Arc::new(Self::default())
    }
}

#[test]
fn a_cloned_template_does_not_share_a_cache_of_its_alpn_or_trust() {
    let provider = provider::default_provider();
    let mut client = make_client_config(KeyType::Rsa2048, &provider);
    client.alpn_protocols = vec![b"first".to_vec()];
    client.handshake_config_resolver = Some(ClientConfigResolver::new(Arc::new(
        CachingClient::default(),
    )));
    let mut other = client.clone();
    other.alpn_protocols = vec![b"second".to_vec()];
    let mut server = make_server_config(KeyType::Rsa2048, &provider);
    server.alpn_protocols = vec![b"first".to_vec(), b"second".to_vec()];
    let server = Arc::new(server);
    let (mut first, mut peer) = make_pair_for_arc_configs(&Arc::new(client), &server);
    do_handshake(&mut first, &mut peer);
    assert_eq!(first.alpn_protocol(), Some(b"first".as_slice()));
    let (mut second, mut peer) = make_pair_for_arc_configs(&Arc::new(other), &server);
    do_handshake(&mut second, &mut peer);
    assert_eq!(second.alpn_protocol(), Some(b"second".as_slice()));
}

#[derive(Debug)]
struct RefuseConnection;

impl ResolvesClientConfig for RefuseConnection {
    fn resolve(&self, _template: &Arc<ClientConfig>) -> Result<Arc<ClientConfig>, Error> {
        Err(Error::General("client configuration unavailable".into()))
    }
    fn clone_for_config(&self) -> Arc<dyn ResolvesClientConfig> {
        Arc::new(Self)
    }
}

impl ResolvesServerConfig for RefuseConnection {
    fn resolve(&self, _template: &Arc<ServerConfig>) -> Result<Arc<ServerConfig>, Error> {
        Err(Error::General("server configuration unavailable".into()))
    }
    fn clone_for_config(&self) -> Arc<dyn ResolvesServerConfig> {
        Arc::new(Self)
    }
}

#[test]
fn a_refusal_reaches_buffered_and_unbuffered_connection_construction() {
    let provider = provider::default_provider();
    let mut client = make_client_config(KeyType::Rsa2048, &provider);
    client.handshake_config_resolver = Some(ClientConfigResolver::new(Arc::new(RefuseConnection)));
    let client = Arc::new(client);
    assert!(
        matches!(ClientConnection::new(client.clone(), server_name("localhost")), Err(Error::General(message)) if message == "client configuration unavailable")
    );
    assert!(
        matches!(rustls::client::UnbufferedClientConnection::new(client, server_name("localhost")), Err(Error::General(message)) if message == "client configuration unavailable")
    );
    let mut server = make_server_config(KeyType::Rsa2048, &provider);
    server.handshake_config_resolver = Some(ServerConfigResolver::new(Arc::new(RefuseConnection)));
    let server = Arc::new(server);
    assert!(
        matches!(ServerConnection::new(server.clone()), Err(Error::General(message)) if message == "server configuration unavailable")
    );
    assert!(
        matches!(rustls::server::UnbufferedServerConnection::new(server), Err(Error::General(message)) if message == "server configuration unavailable")
    );
}

#[test]
fn accepted_client_hello_uses_the_same_connection_time_selection() {
    let provider = provider::default_provider();
    let mut client = ClientConnection::new(
        Arc::new(make_client_config(KeyType::Rsa2048, &provider)),
        server_name("localhost"),
    )
    .unwrap();
    let server = make_server_config(KeyType::Rsa2048, &provider);
    let suite = cipher_suite::TLS13_AES_128_GCM_SHA256;
    let selected = Arc::new(Mutex::new(Arc::new(
        server
            .clone()
            .with_crypto_provider(provider_for(suite))
            .unwrap(),
    )));
    let mut template = server;
    template.handshake_config_resolver = Some(ServerConfigResolver::new(Arc::new(
        ServerSelection(selected),
    )));
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut acceptor = Acceptor::default();
    acceptor
        .read_tls(&mut hello.as_slice())
        .unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    let mut server = accepted
        .into_connection(Arc::new(template))
        .unwrap();
    do_handshake(&mut client, &mut server);
    assert_eq!(server.negotiated_cipher_suite(), Some(suite));
}
