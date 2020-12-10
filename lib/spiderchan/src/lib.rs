use std::{collections::HashMap, hash::Hash, sync::Arc};

use async_channel::{Receiver, Sender};
use async_executor::Executor;
use parking_lot::RwLock;

/// A "spider channel". Messages can be sent to specific topics.
#[derive(Clone)]
pub struct Spider<Addr: Send + Sync + 'static + Eq + Hash + Clone, Item: Send + Sync + 'static> {
    send_msg: Sender<(Addr, Item)>,
    mapping: Arc<RwLock<HashMap<Addr, Sender<Item>>>>,
    exec: Arc<Executor<'static>>,
}

impl<Addr: Send + Sync + 'static + Eq + Hash + Clone, Item: Send + Sync + 'static>
    Spider<Addr, Item>
{
    /// Create a new spider channel with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let exec = Arc::new(Executor::new());
        let (send_msg, recv_msg) = async_channel::bounded(capacity);
        let mapping: Arc<RwLock<HashMap<Addr, Sender<Item>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        exec.spawn(spider_loop(recv_msg, mapping.clone())).detach();
        Self {
            send_msg,
            mapping,
            exec,
        }
    }

    /// Subscribes to a topic, returning a Topic if one doesn't already exist.
    pub fn subscribe(&self, addr: Addr) -> Option<Topic<Addr, Item>> {
        let (send, recv) = async_channel::unbounded();
        {
            let mut mapping = self.mapping.write();
            if mapping.get(&addr).is_some() {
                return None;
            }
            mapping.insert(addr.clone(), send);
        }
        let dropper = Arc::new(TopicDropper {
            addr,
            mapping: self.mapping.clone(),
        });
        Some(Topic {
            recv_item: recv,
            dropper,
            exec: self.exec.clone(),
        })
    }

    /// Sends a message to a topic.
    pub async fn send(&self, addr: Addr, msg: Item) {
        self.exec
            .run(self.send_msg.send((addr, msg)))
            .await
            .unwrap()
    }
}

async fn spider_loop<
    Addr: Send + Sync + 'static + Eq + Hash + Clone,
    Item: Send + Sync + 'static,
>(
    recv_msg: Receiver<(Addr, Item)>,
    mapping: Arc<RwLock<HashMap<Addr, Sender<Item>>>>,
) {
    loop {
        let (addr, item) = recv_msg.recv().await.unwrap();
        if let Some(chan) = mapping.read().get(&addr) {
            let chan = chan.clone();
            let _ = chan.try_send(item);
        }
    }
}

/// Receiving handle for a particular topic
#[derive(Clone)]
pub struct Topic<Addr: Send + Sync + 'static + Eq + Hash + Clone, Item: Send + Sync + 'static> {
    recv_item: Receiver<Item>,
    dropper: Arc<TopicDropper<Addr, Item>>,
    exec: Arc<Executor<'static>>,
}

impl<Addr: Send + Sync + 'static + Eq + Hash + Clone, Item: Send + Sync + 'static>
    Topic<Addr, Item>
{
    /// Receive a message
    pub async fn recv(&self) -> Option<Item> {
        self.exec.run(self.recv_item.recv()).await.ok()
    }
}

struct TopicDropper<Addr: Send + Sync + 'static + Eq + Hash + Clone, Item: Send + Sync + 'static> {
    addr: Addr,
    mapping: Arc<RwLock<HashMap<Addr, Sender<Item>>>>,
}

impl<Addr: Send + Sync + 'static + Eq + Hash + Clone, Item: Send + Sync + 'static> Drop
    for TopicDropper<Addr, Item>
{
    fn drop(&mut self) {
        let mut mapping = self.mapping.write();
        mapping.remove(&self.addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        futures_lite::future::block_on(async {
            let spider = Spider::new(1000);
            let topic = spider.subscribe(12345u16).unwrap();
            spider.send(12345, String::from("hello world")).await;
            spider.send(12345, String::from("dorthisbe")).await;
            dbg!(topic.recv().await.unwrap());
            dbg!(topic.recv().await.unwrap());
        });
    }
}
