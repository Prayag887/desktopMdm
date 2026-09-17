//! Windows desktop UI for the EMI device agent.
//!
//! Split into cohesive submodules to keep each file small:
//! - [`system`] — local probes and persistence helpers
//! - [`app`] — the `DeviceApp` state, the eframe loop, and `run`
//! - [`panels`] — the non-locked tabs (overview, firmware, restriction setup)
//! - [`lock`] — the fullscreen lock screen and owner-token recovery

mod app;
mod lock;
mod panels;
mod system;

pub use app::run;
