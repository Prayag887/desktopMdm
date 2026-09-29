//! Agent binary internals, one responsibility per module.

pub(crate) mod config;
pub(crate) mod enrollment;
pub(crate) mod health;
pub(crate) mod remote_sync;
pub(crate) mod runner;
pub(crate) mod service;
#[cfg(windows)]
pub(crate) mod session_ui;
pub(crate) mod storage;
