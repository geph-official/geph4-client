use std::alloc;

use binary_search::Direction;
use cap::Cap;
use geph4client::dispatch;

#[global_allocator]
static ALLOCATOR: Cap<alloc::System> = Cap::new(alloc::System, usize::max_value());

fn main() -> anyhow::Result<()> {
    ALLOCATOR.set_limit(45 * 1024 * 1024).unwrap();

    #[cfg(any(target_os = "android", target_os = "ios"))]
    smolscale::permanently_single_threaded();

    smolscale::spawn(async {
        loop {
            eprintln!(
                "Currently allocated: {} MB",
                ALLOCATOR.allocated() as f64 / 1_000_000.0
            );
            smol::Timer::after(std::time::Duration::from_secs(1)).await;
        }
    })
    .detach();

    let ((largest_low, _), _) = binary_search::binary_search((1, ()), (65536, ()), |lim| {
        if rlimit::utils::increase_nofile_limit(lim).unwrap_or_default() >= lim {
            Direction::Low(())
        } else {
            Direction::High(())
        }
    });
    let _ = rlimit::utils::increase_nofile_limit(largest_low);
    log::info!("** set fd limit to {} **", largest_low);

    dispatch()
}
