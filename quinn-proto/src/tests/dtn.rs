use std::sync::Arc;
use congestion::NoCCConfig;

use super::*;

fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();

    config.max_idle_timeout(Some(VarInt::MAX.into()));
    config.initial_rtt(Duration::new(100000, 0));

    config.receive_window(VarInt::MAX);
    config.datagram_send_buffer_size(usize::MAX);
    config.send_window(u64::MAX);
    config.datagram_receive_buffer_size(Option::Some(usize::MAX));
    config.stream_receive_window(VarInt::MAX);

    config.congestion_controller_factory(Arc::new(NoCCConfig::default()));

    let mut ack_frequency_config = AckFrequencyConfig::default();
    ack_frequency_config.max_ack_delay(Some(Duration::MAX));
    config.ack_frequency_config(Some(ack_frequency_config));
    //// disable mtu discovery
    let mut mtu_discovery_config = MtuDiscoveryConfig::default();
    mtu_discovery_config.upper_bound(1200);  //should be INITIAL_MTU
    mtu_discovery_config.interval(Duration::new(1000000,0));
    config.mtu_discovery_config(Some(mtu_discovery_config));
    config.packet_threshold(u32::MAX);
    //// so setting a large value
    config.time_threshold(100000.0);

    Arc::new(config)
}

fn client_config() -> ClientConfig {
    let mut config = ClientConfig::new(Arc::new(client_crypto()));
    config.transport_config(transport_config());
    config
}

fn dtn_endpoint_config() -> Arc<EndpointConfig> {
    Arc::new(EndpointConfig::default())
}

fn server_config() -> ServerConfig {
    let mut config = ServerConfig::with_crypto(Arc::new(server_crypto()));
    config.transport_config(transport_config());
    config
}

fn new_dtn_pair() -> Pair {
    let mut pair = Pair::new(dtn_endpoint_config(), server_config());
    pair.latency = Duration::new(30, 0);
    pair
}

fn info_stats(stats: ConnectionStats, side: &str) {

    info!("{} sent datagrams: {}", side, stats.udp_tx.datagrams);
    info!("{} recv datagrams: {}", side, stats.udp_rx.datagrams);
}

#[test]
fn no_cc_no_lost() {
    let _guard = subscribe();
    let mut pair = new_dtn_pair();

    // Drive client side only for 10MB send
    const TRANSFER_SIZE :usize = 10 * 1024 * 1024;

    // Choose incoming and outgoing buffers large enough to hold TRANSFER_SIZE
    pair.client.max_buffers_len = Some(TRANSFER_SIZE / 1024);
    pair.server.max_buffers_len = Some(TRANSFER_SIZE / 1024);

    let (client_ch, server_ch) = pair.connect_with(client_config());
    // pair::connect_with() calls drive() internally 
    let s = pair.client_streams(client_ch).open(Dir::Uni).unwrap();
    info!("Connection established.");

    {
        let mut send = pair.client_send(client_ch, s);
        let c_n = send.write(&[42; TRANSFER_SIZE]).unwrap();
        assert!(c_n == TRANSFER_SIZE);
    }
    pair.drive();

    // There is no retransmission because the buffer is large enough.
    assert!(pair.client_conn_mut(client_ch).stats().path.lost_bytes == 0);
    assert!(pair.server_conn_mut(server_ch).stats().path.lost_bytes == 0);

    // Shrink buffer size
    pair.client.max_buffers_len = Some(pair.client.max_buffers_len.unwrap() / (2 as usize));

    {
        let mut send = pair.client_send(client_ch, s);
        let c_n = send.write(&[42; TRANSFER_SIZE]).unwrap();
        assert!(c_n == TRANSFER_SIZE);
    }
    pair.drive();

    // Lost is observed
    assert!(pair.client_conn_mut(client_ch).stats().path.lost_bytes != 0);

    // Drive close
    info!("closing.");
    const REASON: &[u8] = b"whee";
    pair.client.connections.get_mut(&client_ch).unwrap().close(
        pair.time,
        VarInt(42),
        REASON.into(),
    );
    pair.drive();
}
