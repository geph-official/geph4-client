use std::collections::BTreeSet;

use once_cell::sync::Lazy;

/// List of whitelisted ports.
pub static WHITE_PORTS: Lazy<BTreeSet<u16>> = Lazy::new(|| {
    // See: https://trac.torproject.org/projects/tor/wiki/doc/ReducedExitPolicy
    let mut toret: Vec<_> = vec![
        20u16, 21, 22, 23, 43, 53, 79, 80, 81, 88, 110, 143, 194, 220, 389, 443, 464, 465, 531,
        543, 544, 554, 563, 587, 636, 706, 749, 853, 873, 902, 903, 904, 981, 989, 990, 991, 992,
        993, 994, 995, 1194, 1220, 1293, 1500, 1533, 1677, 1723, 1755, 1863, 2082, 2083, 2086,
        2087, 2095, 2096, 2102, 2104, 3128, 3389, 3690, 4321, 4643, 5050, 5190, 5222, 5223, 5228,
        5900, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 8000, 8008,
        8074, 8080, 8082, 8087, 8088, 8232, 8233, 8332, 8333, 8443, 8888, 9418, 9999, 10000, 11371,
        19294, 19638, 50002, 64738,
    ]
    .into_iter()
    .collect();
    // steam
    toret.extend(27000..=27100);
    toret.extend(&[3748, 4379, 4380]);
    // blizzard
    toret.push(1119);
    toret.extend(3478..=3479);
    toret.into_iter().collect()
});

/// List of blacklisted ports
pub static BLACK_PORTS: Lazy<BTreeSet<u16>> = Lazy::new(|| vec![25u16].into_iter().collect());
