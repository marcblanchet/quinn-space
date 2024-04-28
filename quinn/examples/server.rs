//! This example demonstrates an HTTP server that serves files from a directory.
//!
//! Checkout the `README.md` for guidance.

use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use tracing::{error, info_span};
use tracing_futures::Instrument as _;
use proto::congestion::{BbrConfig, NoCCConfig};
use proto::{AckFrequencyConfig, MtuDiscoveryConfig, VarInt};

mod common;

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    keylog: bool,
    /// directory to serve files from
    root: PathBuf,
    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,

    // sets the congestion control methods. Since cubic is default, options are:
    // "bbr" or "none".
    // The "none" means a cc algo which does no congestion control... (deep space use case)
    #[clap(long = "cc")]
    cc: Option<String>,

    // sets max_idle_timeout to a very large value
    #[clap(long = "large_max_idle_timeout")]
    large_max_idle_timeout: bool,

    // window size
    #[clap(long = "window")]
    window: Option<u32>,

    #[clap(long = "initial_rtt")]
    initial_rtt: Option<u64>,

    // sets many transport config parameters to very large values (such as ::MAX) to handle
    // deep space usage, where delays and disruptions can be in order of minutes, hours, days
    #[clap(long = "dtn")]
    dtn: bool,
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
    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            rustls::PrivateKey(key)
        } else {
            let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
                .context("malformed PKCS #8 private key")?;
            match pkcs8.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                        .context("malformed PKCS #1 private key")?;
                    match rsa.into_iter().next() {
                        Some(x) => rustls::PrivateKey(x),
                        None => {
                            anyhow::bail!("no private keys found");
                        }
                    }
                }
            }
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            vec![rustls::Certificate(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .context("invalid PEM-encoded certificate")?
                .into_iter()
                .map(rustls::Certificate)
                .collect()
        };

        (cert_chain, key)
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::create_dir_all(path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, &key).context("failed to write private key")?;
                (cert, key)
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };

        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
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
        mtu_discovery_config.interval(Duration::new(1000000, 0));
        transport_config.mtu_discovery_config(Some(mtu_discovery_config));
        // max_concurrent_*_streams to VarInt::MAX crashes the process
        //transport_config.max_concurrent_bidi_streams(VarInt::MAX);
        //transport_config.max_concurrent_uni_streams(VarInt::MAX);
        transport_config.packet_threshold(u32::MAX);
        transport_config.time_threshold(f32::MAX);
    }

    if let Some(cc) = options.cc {
        // should use match but can't get it to work with String vs &str.
        if cc == "bbr" {
            transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));
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

    if options.stateless_retry {
        server_config.use_retry(true);
    }

    let root = Arc::<Path>::from(options.root.clone());
    if !root.exists() {
        bail!("root path does not exist");
    }

    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        eprintln!("connection incoming");
        eprintln!(" clock: {:?}", Utc::now());
        let fut = handle_connection(root.clone(), conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

async fn handle_connection(root: Arc<Path>, conn: quinn::Connecting) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        eprintln!("established");
        eprintln!(" clock: {:?}", Utc::now());

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    eprintln!("connection closed");
                    eprintln!(" clock: {:?}", Utc::now());
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(root.clone(), stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                }
                .instrument(info_span!("request")),
            );
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_request(
    root: Arc<Path>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    eprintln!("content = {escaped}");
    eprintln!(" clock: {:?}", Utc::now());
    // Execute the request
    let resp = process_get(&root, &req).unwrap_or_else(|e| {
        error!("failed: {}", e);
        format!("failed to process request: {e}\n").into_bytes()
    });
    // Write the response
    send.write_all(&resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;
    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    eprintln!("complete");
    eprintln!(" clock: {:?}", Utc::now());
    Ok(())
}

fn process_get(root: &Path, x: &[u8]) -> Result<Vec<u8>> {
    if x.len() < 4 || &x[0..4] != b"GET " {
        bail!("missing GET");
    }
    if x[4..].len() < 2 || &x[x.len() - 2..] != b"\r\n" {
        bail!("missing \\r\\n");
    }
    let x = &x[4..x.len() - 2];
    let end = x.iter().position(|&c| c == b' ').unwrap_or(x.len());
    let path = str::from_utf8(&x[..end]).context("path is malformed UTF-8")?;
    let path = Path::new(&path);
    let mut real_path = PathBuf::from(root);
    let mut components = path.components();
    match components.next() {
        Some(path::Component::RootDir) => {}
        _ => {
            bail!("path must be absolute");
        }
    }
    for c in components {
        match c {
            path::Component::Normal(x) => {
                real_path.push(x);
            }
            x => {
                bail!("illegal component in path: {:?}", x);
            }
        }
    }
    let data = fs::read(&real_path).context("failed reading file")?;
    Ok(data)
}
