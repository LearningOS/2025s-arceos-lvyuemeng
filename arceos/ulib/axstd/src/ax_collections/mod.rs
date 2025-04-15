#[cfg(feature = "alloc")]
pub use alloc::collections::*;

pub mod hash_map;
pub use hash_map::HashMap;
