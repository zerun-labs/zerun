//! OCI image engine (M3): image reference parsing, registry pull client,
//! content-addressed blob storage, and read-only rootfs materialization.
//!
//! Storage layout (all under the runtime data root, see `store::Store`):
//!   blobs/sha256/<hex>   raw registry blobs (manifests, configs, layer tars)
//!   rootfs/<hex>         materialized image rootfs, keyed by config digest
//!   images.json          tag index (name/tag -> manifest digest)
//!
//! Engineering notes (deviations from the design doc are deliberate):
//! - Layers are materialized into one read-only rootfs per image *config digest*
//!   instead of mounting each OCI layer as its own overlay lower. Whiteouts are
//!   then plain file deletions during unpack (works rootful *and* rootless, no
//!   mknod needed), and tags sharing the same config digest share one rootfs.
pub mod auth;
pub mod commit;
pub mod config;
pub mod manifest;
pub mod name;
pub mod registry;
pub mod store;
pub mod unpack;

mod pull;

pub use pull::{local_image, pull_image, PullOptions};
