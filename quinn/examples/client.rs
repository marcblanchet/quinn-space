//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::{Instant},
};

use anyhow::{Result, anyhow};
use clap::Parser;
use proto::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tracing::{error, info};
use url::Url;
use proto::congestion::{BbrConfig, CubicConfig};
use proto::congestion::NoCCConfig;
use proto::{AckFrequencyConfig, MtuDiscoveryConfig, TransportConfig};
use proto::{VarInt};
use chrono::Utc;
use tokio::time::{interval, Duration, MissedTickBehavior};
use quinn::{Connection, Endpoint};

mod common;

/// HTTP/0.9 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,

    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long = "host")]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    rebind: bool,

    /// Address to bind on
    #[clap(long = "bind", default_value = "[::]:0")]
    bind: SocketAddr,

    /// sets the congestion control methods. Since cubic is default, options are:
    /// "bbr" or "none".
    /// The "none" means a cc algo which does no congestion control... (deep space use case)
    #[clap(long = "cc")]
    cc: Option<String>,

    /// sets max_idle_timeout to a very large value
    #[clap(long = "large_max_idle_timeout")]
    large_max_idle_timeout: bool,

    /// window size in bytes
    #[clap(long = "window")]
    window: Option<u32>,

    /// congestion initial window size in bytes passed to cc
    #[clap(long = "cc_initial_window")]
    ccwindow: Option<u64>,

    /// sets the initial rtt in ms
    #[clap(long = "initial_rtt")]
    initial_rtt: Option<u64>,


    /// sets many transport config parameters to very large values (such as ::MAX) to handle
    /// deep space usage, where delays and disruptions can be in order of minutes, hours, days
    #[clap(long = "dtn")]
    dtn: bool,

    // insecure mode: do not check the TLS cert from the server
    #[clap(long = "insecure")]
    insecure: bool,

    /// to simulate a single connection with multiple http requests: repeat the same request
    #[clap(long = "repeat")]
    repeat: Option<u32>,

    /// interval in seconds between repeats
    #[clap(long = "repeat-interval")]
    repeat_interval: Option<u64>,

    /// to interop with other stacks, define the alpn
    #[clap(long = "alpn")]
    alpn:  Option<String>,
}

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = Opt::parse();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: Opt) -> Result<()> {
    let url = options.url;
    let url_host = strip_ipv6_brackets(url.host_str().unwrap());
    let remote = (url_host, url.port().unwrap_or(4433))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = options.ca {
        roots.add(CertificateDer::from(fs::read(ca_path)?))?;
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                roots.add(CertificateDer::from(cert))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        //.with_root_certificates(roots)
        .with_no_client_auth();

    if let Some(alpn) = options.alpn {
        client_crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    } else {
        client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    }
    if options.keylog {
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    //TODO: we shall pass on an estimated BDP for the path and then use it for proper calculations
    //  instead of maxing everything
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    //let mut endpoint = quinn::Endpoint::client(options.bind)?;
    let mut transport_config = TransportConfig::default();
     if options.dtn {
        transport_config.max_idle_timeout(Some(VarInt::MAX.into()));
        transport_config.initial_rtt(Duration::new(100000, 0));
        transport_config.receive_window(VarInt::MAX);
        transport_config.datagram_send_buffer_size(usize::MAX);
        transport_config.send_window(u64::MAX);
        transport_config.datagram_receive_buffer_size(Option::Some(usize::MAX));
        transport_config.stream_receive_window(VarInt::MAX);
        transport_config.congestion_controller_factory(Arc::new(NoCCConfig::default()));
        let mut ack_frequency_config = AckFrequencyConfig::default();
        ack_frequency_config.max_ack_delay(Some(Duration::MAX));
        transport_config.ack_frequency_config(Some(ack_frequency_config));
         // disable mtu discovery
         let mut mtu_discovery_config = MtuDiscoveryConfig::default();
         mtu_discovery_config.upper_bound(1200);  //should be INITIAL_MTU
         mtu_discovery_config.interval(Duration::new(1000000,0));
         transport_config.mtu_discovery_config(Some(mtu_discovery_config));
         // max_concurrent_*_streams to VarInt::MAX crashes the process
         //transport_config.max_concurrent_bidi_streams(VarInt::MAX);
         //transport_config.max_concurrent_uni_streams(VarInt::MAX);
         transport_config.packet_threshold(u32::MAX);
         // setting time_threshold to f32::MAX creates a crash at runtime
         // so setting a large value
         transport_config.time_threshold(100000.0);
         // connection_id pool
     }
    if let Some(cc) = options.cc {
        // should use match but can't get it to work with String vs &str.
        let mut window = 100000000;
        if let Some(ccwin) = options.ccwindow {
            window = ccwin;
        }
        if cc == "bbr" {
            let mut bbr_config = BbrConfig::default();
            bbr_config.initial_window(window);
            transport_config.congestion_controller_factory(Arc::new(bbr_config));
        } else if cc == "cubic" {
            let mut cubic_config = CubicConfig::default();
            cubic_config.initial_window(window);
            transport_config.congestion_controller_factory(Arc::new(cubic_config));
        } else if cc == "none" {
            transport_config.congestion_controller_factory(Arc::new(NoCCConfig::default()));
        }
    }
    if options.large_max_idle_timeout {
        transport_config.max_idle_timeout(Some(VarInt::MAX.into()));
    }
    if let Some(window) = options.window {
        transport_config.receive_window(VarInt::from_u32(window));
        transport_config.send_window(window.into());
    }
    if let Some(initial_rtt) = options.initial_rtt {
        transport_config.initial_rtt(Duration::new(initial_rtt,0));
    }
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let start = Instant::now();
    let request = format!("GET {}\r\n", url.path());
    let rebind = options.rebind;
    let host = options.host.as_deref().unwrap_or(url_host);

    eprintln!("clock: {:?}", Utc::now());
    eprintln!("connecting to {host} at {remote}");
    let conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    let conn = Arc::new(conn);
    let request = Arc::new(request);
    let endpoint = Arc::new(endpoint);

    eprintln!("connected at {:?}", start.elapsed());
    eprintln!("clock: {:?}", Utc::now());
    let mut repeat = 1;
    if let Some(repeating) = options.repeat { repeat = repeating; }
    let mut repeat_interval = 0;
    if let Some(repeating_interval) = options.repeat_interval { repeat_interval = repeating_interval; }

    let mut ticker = interval(Duration::from_secs(repeat_interval));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    for n in 0..repeat {
        let conn = conn.clone();
        let request = request.clone();
        let endpoint = endpoint.clone();
        let rebind = rebind;

        tokio::spawn(async move {
            eprintln!(" sending request #{} to remote at: {:?}", n, Utc::now());
            if let Err(e) = perform_request(conn, request, endpoint, rebind, n).await {
                eprintln!("Request failed: {:?}", e);
            }
        });
        ticker.tick().await;
    }

    conn.close(0u32.into(), b"done");
    eprintln!("total time from start to after close: {:?}", start.elapsed());
    eprintln!("clock: {:?}", Utc::now());

    // Give the server a fair chance to receive the close packet
    // eprintln!("pausing to let server close. waiting idle_timeout");
    //endpoint.wait_idle().await;
    //eprintln!("paused to let server close. ending now");
    //eprintln!("clock: {:?}", Utc::now());
    Ok(())
}

async fn perform_request(conn: Arc<Connection>, request: Arc<String>, endpoint: Arc<Endpoint>, rebind: bool, n: u32) -> Result<()> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    if rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        eprintln!("rebinding to {addr}");
        endpoint.rebind(socket).expect("rebind failed");
    }

    let start = Instant::now();
    eprintln!("request #{}: sending at {:?}", n, Utc::now());

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request #{}: {}", n, e))?;

    send.finish()
        .map_err(|e| anyhow!("failed to finish stream of request #{}: {}", n, e))?;

    eprintln!("request #{} sent at {:?}", n, Utc::now());

    let resp = recv
        .read_to_end(usize::MAX)
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;

    let duration = start.elapsed();
    eprintln!(
        "request #{}: response received in {:?} from request start",
        n,
        duration
    );
    io::stdout().write_all(&resp)?;
    io::stdout().flush()?;
    eprintln!("request #{}: duration: {:?}", n, duration);
    eprintln!("request #{}: clock: {:?}", n, Utc::now());
    Ok(())
}



fn strip_ipv6_brackets(host: &str) -> &str {
    // An ipv6 url looks like eg https://[::1]:4433/Cargo.toml, wherein the host [::1] is the
    // ipv6 address ::1 wrapped in brackets, per RFC 2732. This strips those.
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

//fn duration_secs(x: &Duration) -> f32 {
//    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
//}

// copied from insecure_connection.rs. no it is not the right way to do this, but for now, fast enabling testing.
//
// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
