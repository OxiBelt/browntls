//! Prints the CPU features `browntls-crypto` detects and the backend it
//! selects for every algorithm family, so that a fuzz run's log records which
//! code paths it exercised. None of this is sensitive: it describes the
//! machine, not any input.

use browntls_crypto::{accel, cpu};

fn main() {
    println!("browntls-crypto CPU features: {:?}", cpu::features());
    for status in accel::status_all() {
        println!("  {status}");
    }
}
