//! Resident-memory sanity check for the strings the crate frees by hand.
//!
//! Ignored by default: it reads `/proc` and asserts on process memory, which is
//! Linux-only and noisy on a loaded machine. Run it with
//! `cargo test --release -- --ignored --nocapture`.
//!
//! This is the coarse check that works anywhere. `tests/memcheck.rs` does the
//! same job precisely, in bytes rather than pages, when Valgrind is available:
//! `scripts/valgrind-test.sh --test memcheck`.

use modsecurity::{ModSecurity, Rules, Transaction};

fn rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[test]
#[ignore = "memory measurement; run explicitly"]
fn interventions_do_not_leak() {
    let ms = ModSecurity::new().unwrap();
    let mut rules = Rules::new().unwrap();
    rules
        .add_plain(
            "SecRuleEngine On\n\
             SecRule ARGS:a \"@streq 1\" \
             \"id:30000,phase:1,redirect:'https://example.com/somewhere/long',\
             status:302,log,msg:'a reasonably long message to allocate'\"",
        )
        .unwrap();

    let run = |n: usize| {
        for _ in 0..n {
            let mut tx = Transaction::new(&ms, &rules).unwrap();
            tx.process_uri("/?a=1", "GET", "1.1").unwrap();
            let action = tx.process_request_headers().unwrap().expect("intervention");
            assert!(action.url.is_some() && action.log.is_some());
            tx.process_logging().unwrap();
        }
    };

    run(20_000); // warm up allocator arenas
    let before = rss_kib().expect("VmRSS");
    run(200_000);
    let after = rss_kib().expect("VmRSS");

    let growth = after.saturating_sub(before);
    println!("RSS {before} KiB -> {after} KiB ({growth} KiB over 200k transactions)");
    assert!(
        growth < 8 * 1024,
        "RSS grew by {growth} KiB over 200k transactions; suspected leak"
    );
}
