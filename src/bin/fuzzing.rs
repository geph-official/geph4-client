use geph4client::ack_decimate;
use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            ack_decimate(data);
        })
    }
}
