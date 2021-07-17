use std::{collections::VecDeque, net::SocketAddr};

use bimap::BiHashMap;
/// A NAT table. Fundamentally, a bijection between client IP-port pairs and UDP sockets. Automatically handles eviction etc.
pub struct NatTable<T> {
    mapping: BiHashMap<SocketAddr, T>,
    history: VecDeque<SocketAddr>,
    limit: usize,
}

impl<T: Eq + std::hash::Hash + Clone> NatTable<T> {
    /// Creates a NAT table with the given maximum size.
    pub fn new(limit: usize) -> Self {
        Self {
            mapping: Default::default(),
            history: Default::default(),
            limit,
        }
    }

    /// Lookups a client IP-port pair, returning the mapped item. If the mapped item doesn't exist, calls the provided closure to create an item.
    pub fn addr_to_item(&mut self, client_addr: SocketAddr, item_gen: impl FnOnce() -> T) -> T {
        if let Some(val) = self.mapping.get_by_left(&client_addr) {
            val.clone()
        } else {
            self.insert_and_get(client_addr, item_gen()).clone()
        }
    }

    fn insert_and_get(&mut self, client_addr: SocketAddr, item: T) -> &T {
        self.mapping.insert(client_addr, item);
        self.history.push_back(client_addr);
        // clean up history if needed
        assert_eq!(self.history.len(), self.mapping.len());
        while self.history.len() > self.limit {
            let to_del = self.history.pop_front().unwrap();
            self.mapping.remove_by_left(&to_del);
        }
        self.mapping.get_by_left(&client_addr).unwrap()
    }

    /// Lookups a client IP by the item.
    pub fn item_to_addr(&mut self, item: &T) -> Option<SocketAddr> {
        self.mapping.get_by_right(item).copied()
    }
}
