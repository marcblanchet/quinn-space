use crate::congestion::ControllerFactory;
use crate::congestion::Controller;
/// No congestion control
///


use std::any::Any;
use std::sync::Arc;
//use std::time::{Duration, Instant};
use std::time::{Instant};

use crate::connection::RttEstimator;
//use std::cmp;

#[derive(Debug, Default, Clone)]

/// The RFC8312 congestion controller, as widely used for TCP
//#[derive(Debug, Clone)]
pub struct NoCC {
    config: Arc<NoCCConfig>,
    /// Maximum number of bytes in flight that may be sent.
    window: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is
    /// slow start and the window grows by the number of bytes acknowledged.
    ssthresh: u64,
    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: Option<Instant>,
    current_mtu: u64,
}

impl NoCC {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<NoCCConfig>, _now: Instant, current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            ssthresh: u64::MAX,
            recovery_start_time: None,
            config,
            //cubic_state: Default::default(),
            current_mtu: current_mtu as u64,
        }
    }

    fn minimum_window(&self) -> u64 {
        u64::MAX
        //2 * self.current_mtu
    }
}

impl Controller for NoCC {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if app_limited
            || self
            .recovery_start_time
            .map(|recovery_start_time| sent <= recovery_start_time)
            .unwrap_or(false)
        {
            return;
        }

        if self.window < self.ssthresh {
            // Slow start
            self.window = u64::MAX
            //self.window += bytes;
        } else {
            // Congestion avoidance.
            //let ca_start_time;

            //match self.recovery_start_time {
                //Some(t) => ca_start_time = t,
              //  None => {
                    // When we come here without congestion_event() triggered,
                    // initialize congestion_recovery_start_time, w_max and k.
                    //ca_start_time = now;
                    //self.recovery_start_time = Some(now);

                    //self.cubic_state.w_max = self.window as f64;
                    //self.cubic_state.k = 0.0;
               // }
            //}

            //let t = now - ca_start_time;

            // w_cubic(t + rtt)
            //let w_cubic = self.cubic_state.w_cubic(t + rtt.get(), self.current_mtu);

            // w_est(t)
            //let w_est = self.cubic_state.w_est(t, rtt.get(), self.current_mtu);

            //let mut cubic_cwnd = self.window;

            //if w_cubic < w_est {
                // TCP friendly region.
            //    cubic_cwnd = cmp::max(cubic_cwnd, w_est as u64);
            //} else if cubic_cwnd < w_cubic as u64 {
                // Concave region or convex region use same increment.
            //    let cubic_inc =
             //       (w_cubic - cubic_cwnd as f64) / cubic_cwnd as f64 * self.current_mtu as f64;

             //   cubic_cwnd += cubic_inc as u64;
            //}

            // Update the increment and increase cwnd by MSS.
           // self.cubic_state.cwnd_inc += cubic_cwnd - self.window;

            // cwnd_inc can be more than 1 MSS in the late stage of max probing.
            // however RFC9002 §7.3.3 (Congestion Avoidance) limits
            // the increase of cwnd to 1 max_datagram_size per cwnd acknowledged.
           // if self.cubic_state.cwnd_inc >= self.current_mtu {
                self.window = u64::MAX;
                //self.window += self.current_mtu;
           //     self.cubic_state.cwnd_inc = 0;
            //}
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        if self
            .recovery_start_time
            .map(|recovery_start_time| sent <= recovery_start_time)
            .unwrap_or(false)
        {
            return;
        }

        self.recovery_start_time = Some(now);

        // Fast convergence
        //#[allow(clippy::branches_sharing_code)]
        // https://github.com/rust-lang/rust-clippy/issues/7198
        //if (self.window as f64) < self.cubic_state.w_max {
        //    self.cubic_state.w_max = self.window as f64 * (1.0 + BETA_CUBIC) / 2.0;
        //} else {
        //    self.cubic_state.w_max = self.window as f64;
        //}

        //self.ssthresh = cmp::max(
        //    (self.cubic_state.w_max * BETA_CUBIC) as u64,
        //    self.minimum_window(),
        //);
        //self.window = self.ssthresh;
        //self.window = self.minimum_window();
       // self.cubic_state.k = self.cubic_state.cubic_k(self.current_mtu);

        //self.cubic_state.cwnd_inc = (self.cubic_state.cwnd_inc as f64 * BETA_CUBIC) as u64;

        //if is_persistent_congestion {
        //    self.recovery_start_time = None;
        //    self.cubic_state.w_max = self.window as f64;

            // 4.7 Timeout - reduce ssthresh based on BETA_CUBIC
        //    self.ssthresh = cmp::max(
         //       (self.window as f64 * BETA_CUBIC) as u64,
         //       self.minimum_window(),
         //   );

        //    self.cubic_state.cwnd_inc = 0;

        //    self.window = self.minimum_window();
        //}
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `Cubic` congestion controller
#[derive(Debug, Clone)]
pub struct NoCCConfig {
    initial_window: u64,
}

impl NoCCConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for NoCCConfig {
    fn default() -> Self {
        Self {
            // set to the largest possible value (aka almost infinite)
            initial_window: u64::MAX
            //initial_window: 14720.clamp(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE),
        }
    }
}

impl ControllerFactory for NoCCConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoCC::new(self, now, current_mtu))
    }
}
