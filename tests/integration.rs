//! End-to-end tests against the real libmodsecurity.

use std::sync::{Arc, Mutex};

use modsecurity::{Error, ModSecurity, Rules, Transaction};

fn engine() -> ModSecurity {
    ModSecurity::new()
        .expect("msc_init")
        .with_connector_info("modsecurity-rs-tests/0.1")
        .expect("connector info")
}

fn rules_from(text: &str) -> Rules {
    let mut rules = Rules::new().expect("rules set");
    rules.add_plain(text).expect("rules parse");
    rules
}

#[test]
fn reports_engine_version() {
    let who = engine().who_am_i();
    assert!(who.contains("ModSecurity"), "unexpected banner: {who}");
    assert!(who.contains("v3."), "expected a v3 library, got: {who}");
}

#[test]
fn clean_request_is_not_disrupted() {
    let ms = engine();
    let rules = rules_from(
        "SecRuleEngine On\n\
         SecRule ARGS:attack \"@streq 1\" \"id:1000,phase:1,deny,status:403\"",
    );

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    assert!(
        tx.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
            .unwrap()
            .is_none()
    );
    assert!(
        tx.process_uri("/index.html?q=hello", "GET", "1.1")
            .unwrap()
            .is_none()
    );
    tx.add_request_header(b"Host", b"example.com").unwrap();
    assert!(tx.process_request_headers().unwrap().is_none());
    assert!(tx.process_request_body().unwrap().is_none());
    tx.process_logging().unwrap();
}

#[test]
fn matching_rule_produces_intervention() {
    let ms = engine();
    let rules = rules_from(
        "SecRuleEngine On\n\
         SecRule ARGS:attack \"@streq 1\" \
         \"id:1000,phase:1,deny,status:403,log,msg:'test blocked'\"",
    );

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_connection("127.0.0.1", 12345, "127.0.0.1", 80)
        .unwrap();
    tx.process_uri("/index.html?attack=1", "GET", "1.1")
        .unwrap();
    tx.add_request_header(b"Host", b"example.com").unwrap();

    let action = tx
        .process_request_headers()
        .unwrap()
        .expect("rule 1000 should have intervened");

    assert!(action.disruptive);
    assert_eq!(action.status, 403);
    let log = action
        .log_message()
        .expect("intervention carries a log line");
    assert!(log.contains("test blocked"), "unexpected log line: {log}");

    // The intervention is reported once and then cleared.
    assert!(tx.intervention().is_none());
    tx.process_logging().unwrap();
}

#[test]
fn redirect_action_carries_a_url() {
    let ms = engine();
    let rules = rules_from(
        "SecRuleEngine On\n\
         SecRule REQUEST_URI \"@contains /old\" \
         \"id:1100,phase:1,redirect:'https://example.com/new',status:302\"",
    );

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_uri("/old/page", "GET", "1.1").unwrap();
    let action = tx.process_request_headers().unwrap().expect("redirect");

    assert_eq!(action.redirect_url(), Some("https://example.com/new"));
    tx.process_logging().unwrap();
}

#[test]
fn request_body_is_inspected() {
    let ms = engine();
    let rules = rules_from(
        "SecRuleEngine On\n\
         SecRequestBodyAccess On\n\
         SecRule REQUEST_BODY \"@contains ' OR 1=1'\" \
         \"id:1200,phase:2,deny,status:418\"",
    );

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_uri("/login", "POST", "1.1").unwrap();
    tx.add_request_header(b"Content-Type", b"application/x-www-form-urlencoded")
        .unwrap();
    tx.process_request_headers().unwrap();

    assert!(
        tx.append_request_body(b"user=admin&pass=x")
            .unwrap()
            .is_none()
    );
    assert!(tx.append_request_body(b"' OR 1=1'").unwrap().is_none());
    assert_eq!(tx.request_body_length(), 26);

    let action = tx.process_request_body().unwrap().expect("body rule");
    assert_eq!(action.status, 418);
    tx.process_logging().unwrap();
}

#[test]
fn response_phases_run() {
    let ms = engine();
    let rules = rules_from(
        "SecRuleEngine On\n\
         SecResponseBodyAccess On\n\
         SecResponseBodyMimeType text/plain\n\
         SecRule RESPONSE_BODY \"@contains SECRET\" \"id:1300,phase:4,deny,status:500\"",
    );

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_uri("/", "GET", "1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.add_response_header(b"Content-Type", b"text/plain")
        .unwrap();
    tx.process_response_headers(200, "HTTP/1.1").unwrap();
    tx.append_response_body(b"this body contains SECRET data")
        .unwrap();
    assert_eq!(tx.response_body_length(), 30);

    let action = tx.process_response_body().unwrap().expect("response rule");
    assert_eq!(action.status, 500);

    tx.update_status_code(500).unwrap();
    tx.process_logging().unwrap();
}

#[test]
fn headers_may_contain_arbitrary_bytes() {
    let ms = engine();
    let rules = rules_from("SecRuleEngine On");
    let mut tx = Transaction::new(&ms, &rules).unwrap();

    // Explicit lengths mean embedded NULs and non-UTF-8 are fine.
    tx.add_request_header(b"X-Weird", b"a\0b\xff").unwrap();
    tx.add_request_header(b"X-Bin\0ary", &[0xc3, 0x28]).unwrap();
    tx.process_request_headers().unwrap();
    tx.process_logging().unwrap();
}

#[test]
fn rule_syntax_errors_are_reported() {
    let mut rules = Rules::new().unwrap();
    let err = rules
        .add_plain("SecRule NOT_A_VARIABLE \"@totally_bogus x\" \"id:1\"")
        .unwrap_err();
    match err {
        Error::Rules(msg) => assert!(!msg.is_empty(), "empty parser diagnostic"),
        other => panic!("expected Error::Rules, got {other:?}"),
    }
}

#[test]
fn missing_rule_file_is_reported() {
    let mut rules = Rules::new().unwrap();
    let err = rules
        .add_file("/nonexistent/modsecurity-rs/rules.conf")
        .unwrap_err();
    assert!(matches!(err, Error::Rules(_)), "got {err:?}");
}

#[test]
fn interior_nul_is_an_error_not_a_panic() {
    let ms = engine();
    let rules = rules_from("SecRuleEngine On");
    let mut tx = Transaction::new(&ms, &rules).unwrap();

    assert_eq!(
        tx.process_uri("/a\0b", "GET", "1.1").unwrap_err(),
        Error::InteriorNul("uri")
    );
    assert_eq!(
        tx.process_connection("127.0.0.1\0", 1, "127.0.0.1", 2)
            .unwrap_err(),
        Error::InteriorNul("client_ip")
    );
    assert_eq!(
        Rules::new()
            .unwrap()
            .add_plain("SecRuleEngine\0 On")
            .unwrap_err(),
        Error::InteriorNul("rules")
    );
}

/// A non-disruptive match: libmodsecurity reports these through the log
/// callback. Disruptive matches carry their message in the intervention
/// instead, and do not reach the callback.
const WARNING_RULE: &str = "SecRuleEngine On\n\
     SecRule ARGS:attack \"@streq 1\" \"id:1400,phase:1,pass,log,msg:'callback test'\"";

#[test]
fn log_callback_receives_messages() {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);

    let mut ms = engine();
    ms.set_log_callback(move |msg: &[u8]| {
        sink.lock()
            .unwrap()
            .push(String::from_utf8_lossy(msg).into_owned());
    });

    let rules = rules_from(WARNING_RULE);

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_uri("/?attack=1", "GET", "1.1").unwrap();
    assert!(
        tx.process_request_headers().unwrap().is_none(),
        "pass is not disruptive"
    );
    tx.process_logging().unwrap();
    drop(tx);

    let messages = seen.lock().unwrap();
    assert!(!messages.is_empty(), "log callback was never invoked");
    assert!(
        messages.iter().any(|m| m.contains("callback test")),
        "message not found in {messages:?}"
    );
}

#[test]
fn log_callbacks_are_per_handle() {
    let a_seen = Arc::new(Mutex::new(0usize));
    let b_seen = Arc::new(Mutex::new(0usize));

    let mut a = engine();
    let mut b = engine();
    let (ca, cb) = (Arc::clone(&a_seen), Arc::clone(&b_seen));
    a.set_log_callback(move |_| *ca.lock().unwrap() += 1);
    b.set_log_callback(move |_| *cb.lock().unwrap() += 1);

    let rules = rules_from(WARNING_RULE);
    let mut tx = Transaction::new(&a, &rules).unwrap();
    tx.process_uri("/?attack=1", "GET", "1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_logging().unwrap();
    drop(tx);

    assert!(*a_seen.lock().unwrap() > 0, "handle a saw nothing");
    assert_eq!(
        *b_seen.lock().unwrap(),
        0,
        "handle b saw another handle's logs"
    );
}

#[test]
fn dropping_a_handle_does_not_disturb_others() {
    // The engine is a process-wide singleton that is never destroyed, so a
    // dropped handle must leave every other handle working.
    let kept = engine();
    for _ in 0..16 {
        let scratch = engine();
        assert!(scratch.who_am_i().contains("ModSecurity"));
    }
    let rules = rules_from("SecRuleEngine On");
    let mut tx = Transaction::new(&kept, &rules).unwrap();
    tx.process_uri("/", "GET", "1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_logging().unwrap();
}

#[test]
fn panicking_log_callback_does_not_unwind_into_cxx() {
    let mut ms = engine();
    ms.set_log_callback(|_| panic!("callback blew up"));

    let rules = rules_from(WARNING_RULE);

    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_uri("/?attack=1", "GET", "1.1").unwrap();
    // Would abort the process if the panic escaped the trampoline.
    tx.process_request_headers().unwrap();
    tx.process_logging().unwrap();
}

#[test]
fn rule_sets_can_be_parsed_concurrently() {
    // The SecLang parser has global state; the crate serialises it. Without
    // that lock this interleaves diagnostics and corrupts the heap.
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                for n in 0..40 {
                    let id = 20_000 + i * 100 + n;
                    let mut rules = Rules::new().unwrap();
                    rules.add_plain("SecRuleEngine On").unwrap();
                    rules
                        .add_plain(&format!(
                            "SecRule ARGS:a \"@streq 1\" \"id:{id},phase:1,deny,status:403\""
                        ))
                        .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

#[test]
fn rules_can_be_merged() {
    let mut base = Rules::new().unwrap();
    base.add_plain("SecRuleEngine On").unwrap();

    let mut extra = Rules::new().unwrap();
    extra
        .add_plain("SecRule ARGS:attack \"@streq 1\" \"id:1600,phase:1,deny,status:403\"")
        .unwrap();

    base.merge(&extra).unwrap();
    drop(extra); // merging copies; the source is still independently owned.

    let ms = engine();
    let mut tx = Transaction::new(&ms, &base).unwrap();
    tx.process_uri("/?attack=1", "GET", "1.1").unwrap();
    assert!(tx.process_request_headers().unwrap().is_some());
    tx.process_logging().unwrap();
}

#[test]
fn engine_and_rules_are_shareable_across_threads() {
    let ms = Arc::new(engine());
    let rules = Arc::new(rules_from(
        "SecRuleEngine On\n\
         SecRule ARGS:attack \"@streq 1\" \"id:1700,phase:1,deny,status:403\"",
    ));

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let ms = Arc::clone(&ms);
            let rules = Arc::clone(&rules);
            std::thread::spawn(move || {
                for n in 0..50 {
                    let mut tx = Transaction::with_id(&ms, &rules, &format!("t{i}-{n}")).unwrap();
                    let uri = if n % 2 == 0 {
                        "/?attack=1"
                    } else {
                        "/?attack=0"
                    };
                    tx.process_uri(uri, "GET", "1.1").unwrap();
                    let blocked = tx.process_request_headers().unwrap().is_some();
                    assert_eq!(blocked, n % 2 == 0);
                    tx.process_logging().unwrap();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("worker thread panicked");
    }
}

#[test]
fn transaction_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Transaction<'_>>();
    assert_send::<ModSecurity>();
    assert_send::<Rules>();

    let ms = engine();
    let rules = rules_from("SecRuleEngine On");
    let mut tx = Transaction::new(&ms, &rules).unwrap();
    tx.process_uri("/", "GET", "1.1").unwrap();

    std::thread::scope(|s| {
        s.spawn(move || {
            tx.process_request_headers().unwrap();
            tx.process_logging().unwrap();
        });
    });
}
