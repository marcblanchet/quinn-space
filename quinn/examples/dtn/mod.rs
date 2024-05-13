
use std::{
    sync::Weak,
    time::Duration,
};

pub async fn lost_bytes_monitor(conn: Weak<quinn::Connection>) {
    eprintln!("Connection monitor started");
    loop {
        match conn.upgrade() {
            Some(c) => {
                if c.stats().path.lost_bytes > 0 {
                    eprintln!("Lost bytes in testing mode: {}", c.stats().path.lost_bytes); 
                    c.close(0u32.into(), b"Lost bytes in testing mode");
                }
            }
            None => { break; }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}



