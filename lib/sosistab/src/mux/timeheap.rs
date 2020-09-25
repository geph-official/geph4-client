use std::{collections::BinaryHeap, time::Instant};

#[derive(Debug)]
/// A priority queue of future events.
pub struct TimeHeap<T: Ord> {
    heap: BinaryHeap<(Instant, T)>,
}
