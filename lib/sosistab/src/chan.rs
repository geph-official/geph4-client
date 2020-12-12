use smol::channel::Receiver;

/// Reads multiple messages from a channel.
pub async fn recv_many<T>(ch: &Receiver<T>) -> Result<Vec<T>, smol::channel::RecvError> {
    let mut buf = Vec::with_capacity(16);
    // try_recv as much as possible
    while let Ok(val) = ch.try_recv() {
        buf.push(val);
    }
    buf.push(ch.recv().await?);
    Ok(buf)
}
