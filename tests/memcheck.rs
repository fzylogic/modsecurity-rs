//! Memory-correctness tests driven from inside Valgrind, via crabgrind.
//!
//! `tests/integration.rs` checks behaviour; this file checks what the FFI layer
//! does to the heap. Running that suite under Memcheck already catches invalid
//! accesses anywhere in the crate. These tests add what an outside-in Valgrind
//! run cannot do: they take leak and error counts *around a specific workload*,
//! so one-time start-up allocations — including the engine singleton this crate
//! deliberately never frees — cancel out, and what remains is attributable.
//!
//! Built only with `--features valgrind`, and run by:
//!
//! ```text
//! scripts/valgrind-test.sh --test memcheck
//! ```
//!
//! Without Valgrind every client request is a no-op, so each test reports that
//! it was skipped and passes — unless `MODSEC_REQUIRE_VALGRIND` is set, which
//! the script does, making a vacuous pass impossible.

use std::ffi::CString;
use std::sync::{Mutex, MutexGuard};

use crabgrind as cg;
use cg::memcheck::{LeakCheck, LeaksCount};
use cg::valgrind;

use modsecurity::{Intervention, ModSecurity, Rules, Transaction};

/// Memcheck's leak and error counters are process-wide, so only one test may be
/// measuring at a time. `scripts/valgrind-test.sh` also pins the harness to one
/// thread; this lock keeps the file correct if someone runs it without that.
static MEASURING: Mutex<()> = Mutex::new(());

fn measuring() -> MutexGuard<'static, ()> {
    MEASURING.lock().unwrap_or_else(|p| p.into_inner())
}

/// Returns `false` once, with an explanation, when this binary is not running
/// under Valgrind — or panics if the caller demanded Valgrind.
#[must_use]
fn under_valgrind(test: &str) -> bool {
    if valgrind::running_mode().is_valgrind() {
        return true;
    }
    assert!(
        std::env::var_os("MODSEC_REQUIRE_VALGRIND").is_none(),
        "{test}: MODSEC_REQUIRE_VALGRIND is set, but this binary is not running \
         under Valgrind, so the measurement would be meaningless"
    );
    eprintln!("skipping {test}: not running under Valgrind (use scripts/valgrind-test.sh)");
    false
}

/// Writes a line into Valgrind's own output, so a failure report says which
/// phase of which test the surrounding records came from.
fn annotate(msg: &str) {
    if let Ok(line) = CString::new(format!("--- {msg} ---\n")) {
        cg::vg_print(&line);
    }
}

/// Takes the baseline for a measurement.
///
/// `VALGRIND_COUNT_LEAKS` reports cumulative totals as of the last check rather
/// than a delta, so a measurement is a baseline, a workload, and a closing
/// check. The baseline uses a summary scan: its per-block detail would only
/// describe allocations that are about to be subtracted away, and each full
/// scan prints a leak report into Valgrind's log.
fn baseline() -> LeaksCount {
    LeakCheck::Quick.check()
}

/// Closes a measurement with a complete scan, so that if the assertion below
/// fails, Valgrind's log already holds the stack trace of every leaked block.
fn leak_totals() -> LeaksCount {
    LeakCheck::Full.check()
}

/// Asserts that a workload added no leaked or possibly-leaked bytes.
///
/// `reachable` is deliberately not asserted on: the engine singleton and
/// libmodsecurity's global state live there by design.
fn assert_no_new_leaks(what: &str, before: LeaksCount, after: LeaksCount) {
    let leaked = after.leaked as i128 - before.leaked as i128;
    let dubious = after.dubious as i128 - before.dubious as i128;
    println!(
        "{what}: leaked {:+} B, possibly-lost {:+} B \
         (absolute: {} leaked, {} dubious, {} reachable, {} suppressed)",
        leaked, dubious, after.leaked, after.dubious, after.reachable, after.suppressed
    );
    assert_eq!(leaked, 0, "{what} leaked {leaked} bytes");
    assert_eq!(dubious, 0, "{what} possibly leaked {dubious} bytes");
}

/// Rules whose disruptive action allocates both an intervention URL and a log
/// message — the two `strdup`ed strings this crate frees by hand.
const REDIRECT_RULES: &str = "SecRuleEngine On\n\
     SecRule ARGS:a \"@streq 1\" \
     \"id:40000,phase:1,redirect:'https://example.com/a/fairly/long/target/path',\
     status:302,log,msg:'an intervention message long enough to reach the heap'\"";

/// One transaction that matches `REDIRECT_RULES`, exercising the full phase
/// sequence and the intervention string handling.
fn disrupted_transaction(ms: &ModSecurity, rules: &Rules) -> Intervention {
    let mut tx = Transaction::new(ms, rules).unwrap();
    tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443).unwrap();
    tx.process_uri("/page?a=1", "GET", "1.1").unwrap();
    tx.add_request_header(b"Host", b"example.com").unwrap();
    let action = tx.process_request_headers().unwrap().expect("redirect");
    tx.process_logging().unwrap();
    action
}

#[test]
fn crabgrind_is_wired_up() {
    let _guard = measuring();
    // Compile-time: a crabgrind built without its `valgrind` feature turns
    // every client request into a no-op, which would make this whole file pass
    // while measuring nothing.
    const {
        assert!(
            cg::VALGRIND_AVAILABLE,
            "crabgrind was built without Valgrind support; client requests are no-ops"
        );
    }
    if !under_valgrind("crabgrind_is_wired_up") {
        return;
    }
    annotate("modsecurity-rs: crabgrind_is_wired_up");

    assert!(valgrind::running_mode().is_valgrind());

    // Keep an engine alive so the heap definitely holds something reachable.
    // If the client requests were silently no-ops these counters would be zero,
    // and every other test in this file would pass without measuring anything.
    let ms = ModSecurity::new().unwrap();
    assert!(ms.who_am_i().contains("ModSecurity"));

    let totals = LeakCheck::Full.check();
    assert!(
        totals.reachable > 0,
        "leak check reported nothing reachable; crabgrind is not talking to Valgrind"
    );
    println!(
        "Valgrind {}.{}, {} B reachable at baseline",
        cg::VALGRIND_VERSION.0,
        cg::VALGRIND_VERSION.1,
        totals.reachable
    );
}

#[test]
fn transactions_do_not_leak() {
    let _guard = measuring();
    if !under_valgrind("transactions_do_not_leak") {
        return;
    }
    annotate("modsecurity-rs: transactions_do_not_leak");

    let ms = ModSecurity::new().unwrap();
    let mut rules = Rules::new().unwrap();
    rules.add_plain(REDIRECT_RULES).unwrap();

    // Warm up: the engine singleton, the rules set and libmodsecurity's lazy
    // global state all allocate on first use and must land before the baseline.
    for _ in 0..50 {
        let action = disrupted_transaction(&ms, &rules);
        assert_eq!(action.status, 302);
    }

    let before = baseline();
    for _ in 0..500 {
        let action = disrupted_transaction(&ms, &rules);
        // Both `strdup`ed strings are present, copied and freed by the wrapper.
        assert!(action.redirect_url().is_some());
        assert!(action.log_message().is_some());
    }
    let after = leak_totals();

    assert_no_new_leaks("500 disrupted transactions", before, after);
}

#[test]
fn transaction_bodies_do_not_leak() {
    let _guard = measuring();
    if !under_valgrind("transaction_bodies_do_not_leak") {
        return;
    }
    annotate("modsecurity-rs: transaction_bodies_do_not_leak");

    let ms = ModSecurity::new().unwrap();
    let mut rules = Rules::new().unwrap();
    rules
        .add_plain(
            "SecRuleEngine On\n\
             SecRequestBodyAccess On\n\
             SecResponseBodyAccess On\n\
             SecResponseBodyMimeType text/plain\n\
             SecRule REQUEST_BODY \"@contains needle\" \"id:40100,phase:2,pass,log\"",
        )
        .unwrap();

    let body = vec![b'x'; 16 * 1024];

    let run = |n: usize| {
        for _ in 0..n {
            let mut tx = Transaction::new(&ms, &rules).unwrap();
            tx.process_uri("/upload", "POST", "1.1").unwrap();
            tx.add_request_header(b"Content-Type", b"application/octet-stream").unwrap();
            tx.process_request_headers().unwrap();
            tx.append_request_body(&body).unwrap();
            tx.append_request_body(b"needle").unwrap();
            tx.process_request_body().unwrap();
            tx.add_response_header(b"Content-Type", b"text/plain").unwrap();
            tx.process_response_headers(200, "HTTP/1.1").unwrap();
            tx.append_response_body(&body).unwrap();
            tx.process_response_body().unwrap();
            tx.update_status_code(200).unwrap();
            tx.process_logging().unwrap();
        }
    };

    run(20);
    let before = baseline();
    run(100);
    let after = leak_totals();

    assert_no_new_leaks("100 transactions with 16 KiB bodies", before, after);
}

#[test]
fn rule_sets_do_not_leak() {
    let _guard = measuring();
    if !under_valgrind("rule_sets_do_not_leak") {
        return;
    }
    annotate("modsecurity-rs: rule_sets_do_not_leak");

    // Builds, parses, merges and drops rule sets, including the failure path
    // that hands back a `strdup`ed parser diagnostic for the wrapper to free.
    let cycle = |n: usize| {
        for i in 0..n {
            let mut rules = Rules::new().unwrap();
            rules.add_plain("SecRuleEngine On").unwrap();
            rules
                .add_plain(&format!(
                    "SecRule ARGS:a \"@streq 1\" \"id:{},phase:1,deny,status:403\"",
                    41_000 + i
                ))
                .unwrap();

            let mut extra = Rules::new().unwrap();
            extra
                .add_plain(&format!(
                    "SecRule REQUEST_URI \"@contains /x\" \"id:{},phase:1,pass,log\"",
                    42_000 + i
                ))
                .unwrap();
            rules.merge(&extra).unwrap();

            // Error paths allocate a diagnostic that `Rules` must free.
            let err = rules.add_plain("SecRule BOGUS \"@nope x\" \"id:1\"").unwrap_err();
            assert!(!err.to_string().is_empty());
            let err = rules.add_file("/nonexistent/modsecurity-rs.conf").unwrap_err();
            assert!(!err.to_string().is_empty());
        }
    };

    cycle(5);
    let before = baseline();
    cycle(25);
    let after = leak_totals();

    assert_no_new_leaks("25 rule-set build/merge/error cycles", before, after);
}

#[test]
fn log_callbacks_do_not_leak() {
    let _guard = measuring();
    if !under_valgrind("log_callbacks_do_not_leak") {
        return;
    }
    annotate("modsecurity-rs: log_callbacks_do_not_leak");

    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = std::sync::Arc::clone(&seen);

    let mut ms = ModSecurity::new().unwrap();
    ms.set_log_callback(move |msg: &[u8]| {
        // Touch every byte, so Memcheck checks the whole slice is addressable
        // and defined — this is the pointer the C++ side handed the trampoline.
        let n = msg.iter().filter(|b| **b != 0).count();
        sink.fetch_add(n.min(1), std::sync::atomic::Ordering::Relaxed);
    });

    let mut rules = Rules::new().unwrap();
    rules
        .add_plain(
            "SecRuleEngine On\n\
             SecRule ARGS:a \"@streq 1\" \"id:43000,phase:1,pass,log,msg:'warning path'\"",
        )
        .unwrap();

    let run = |n: usize| {
        for _ in 0..n {
            let mut tx = Transaction::new(&ms, &rules).unwrap();
            tx.process_uri("/?a=1", "GET", "1.1").unwrap();
            assert!(tx.process_request_headers().unwrap().is_none());
            tx.process_logging().unwrap();
        }
    };

    run(20);
    let before = baseline();
    run(200);
    let after = leak_totals();

    assert!(
        seen.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "log callback never fired, so nothing was measured"
    );
    assert_no_new_leaks("200 transactions through the log trampoline", before, after);
}

#[test]
fn api_surface_raises_no_memcheck_errors() {
    let _guard = measuring();
    if !under_valgrind("api_surface_raises_no_memcheck_errors") {
        return;
    }
    annotate("modsecurity-rs: api_surface_raises_no_memcheck_errors");

    let before = valgrind::count_errors();

    let mut ms = ModSecurity::new().unwrap();
    ms.set_connector_info("memcheck/0.1").unwrap();
    ms.set_log_callback(|msg: &[u8]| {
        std::hint::black_box(msg.len());
    });
    let _ = ms.who_am_i();

    let mut rules = Rules::new().unwrap();
    rules.add_plain(REDIRECT_RULES).unwrap();

    // Binary header names and values: these cross the boundary as explicit
    // pointer/length pairs, so Memcheck verifies libmodsecurity reads exactly
    // the bytes it was given and no further.
    let mut tx = Transaction::with_id(&ms, &rules, "memcheck-0001").unwrap();
    tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443).unwrap();
    tx.process_uri("/page?a=1", "GET", "1.1").unwrap();
    tx.add_request_header(b"X-Binary", &[0x00, 0xff, 0xc3, 0x28]).unwrap();
    tx.add_request_header(b"X-Embedded\0Nul", b"value").unwrap();
    tx.add_request_header(b"", b"").unwrap();
    let action = tx.process_request_headers().unwrap().expect("redirect");
    std::hint::black_box((action.status, action.url, action.log));
    tx.process_logging().unwrap();
    drop(tx);

    // Error paths, which allocate and free diagnostics.
    assert!(rules.add_plain("SecRule BOGUS \"@nope x\" \"id:2\"").is_err());
    assert!(Rules::new().unwrap().add_plain("Sec\0RuleEngine On").is_err());

    let after = valgrind::count_errors();
    println!("memcheck errors: {before} -> {after}");
    assert_eq!(
        after, before,
        "Memcheck reported {} new error(s); see the Valgrind log above",
        after - before
    );
}
