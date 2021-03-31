use smol::channel::Receiver;

// /// Batch receive from a channel
// #[inline]
// pub(crate) async fn batch_recv_into<T>(
//     chan: &Receiver<T>,
//     out: &mut Vec<T>,
// ) -> Result<usize, smol::channel::RecvError> {
//     out.push(chan.recv().await?);
//     let mut count = 1;
//     while let Ok(elem) = chan.try_recv() {
//         if count >= 128 {
//             break;
//         }
//         out.push(elem);
//         count += 1;
//     }
//     Ok(count)
// }

/// Batch receive from a channel
#[inline]
pub(crate) async fn batch_recv<T>(chan: &Receiver<T>) -> Result<Vec<T>, smol::channel::RecvError> {
    let mut out = Vec::with_capacity(128);
    out.push(chan.recv().await?);
    let mut count = 1;
    while let Ok(elem) = chan.try_recv() {
        if count >= 128 {
            break;
        }
        out.push(elem);
        count += 1;
    }
    Ok(out)
}
