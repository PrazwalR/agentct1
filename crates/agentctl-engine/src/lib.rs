//! agentctl optional Rust hot-path sidecar.
//!
//! For operators screening high payment volume, this service does signature
//! inspection (EIP-3009 / Permit2 EIP-712 digest + signer recovery) and
//! behavioral anomaly scoring (Isolation Forest) at native speed, mirroring the
//! TypeScript engine so the hot path can be offloaded.

pub mod api;
pub mod behavioral;
pub mod sig_inspect;
