use core::hash::{BuildHasher, Hash, Hasher};

pub type HashMap<K, V> = hashbrown::HashMap<K, V>;