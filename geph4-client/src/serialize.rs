use std::ops::DerefMut;

use serde::Serialize;
use sosistab::{Buff, BuffMut};

pub fn serialize<T: Serialize>(val: &T) -> Buff {
    let mut bmut = BuffMut::new();
    bincode::serialize_into(bmut.deref_mut(), val).unwrap();
    bmut.freeze()
}
