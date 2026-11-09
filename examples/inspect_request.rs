//! Inspects a request through a full ModSecurity transaction.
//!
//! Run with the bundled demo rules:
//!
//! ```text
//! cargo run --example inspect_request -- "/search?q=%3Cscript%3E"
//! cargo run --example inspect_request -- /index.html
//! ```
//!
//! Pass a rules file as a second argument to use real rules, e.g. the OWASP
//! Core Rule Set:
//!
//! ```text
//! cargo run --example inspect_request -- /index.html /etc/modsecurity.d/include.conf
//! ```

use std::process::ExitCode;

use modsecurity::{Intervention, ModSecurity, Rules, Transaction};

/// Stand-in rules, so the example runs with nothing installed.
const DEMO_RULES: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On

SecRule ARGS "@detectXSS" \
    "id:9001,phase:2,deny,status:403,log,msg:'XSS detected in ARGS'"
SecRule ARGS "@detectSQLi" \
    "id:9002,phase:2,deny,status:403,log,msg:'SQL injection detected in ARGS'"
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto nmap" \
    "id:9003,phase:1,deny,status:403,log,msg:'Scanner user agent'"
SecRule REQUEST_URI "@contains /etc/passwd" \
    "id:9004,phase:1,pass,log,msg:'Suspicious path, allowed but logged'"
"#;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let uri = args
        .next()
        .unwrap_or_else(|| "/search?q=%3Cscript%3E".into());
    let rules_file = args.next();

    match inspect(&uri, rules_file.as_deref()) {
        Ok(None) => {
            println!("ALLOW  {uri}");
            ExitCode::SUCCESS
        }
        Ok(Some(action)) => {
            println!("BLOCK  {uri}");
            println!("  status : {}", action.status);
            if let Some(url) = action.redirect_url() {
                println!("  redirect: {url}");
            }
            if let Some(log) = action.log_message() {
                println!("  rule   : {log}");
            }
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn inspect(uri: &str, rules_file: Option<&str>) -> modsecurity::Result<Option<Intervention>> {
    // One engine and one rules set per process; share them across threads.
    let mut ms = ModSecurity::new()?.with_connector_info("inspect-request/0.1")?;
    ms.set_log_callback(|msg: &[u8]| {
        // Non-disruptive matches arrive here; disruptive ones come back as an
        // intervention instead.
        eprintln!("log: {}", String::from_utf8_lossy(msg));
    });

    let mut rules = Rules::new()?;
    match rules_file {
        Some(path) => {
            rules.add_file(path)?;
        }
        None => {
            rules.add_plain(DEMO_RULES)?;
        }
    }

    // One transaction per request.
    let mut tx = Transaction::with_id(&ms, &rules, "req-0001")?;

    let outcome = (|| -> modsecurity::Result<Option<Intervention>> {
        if let Some(a) = tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443)? {
            return Ok(Some(a));
        }
        if let Some(a) = tx.process_uri(uri, "POST", "1.1")? {
            return Ok(Some(a));
        }

        tx.add_request_header(b"Host", b"example.com")?;
        tx.add_request_header(b"User-Agent", b"curl/8.5.0")?;
        tx.add_request_header(b"Content-Type", b"application/x-www-form-urlencoded")?;
        if let Some(a) = tx.process_request_headers()? {
            return Ok(Some(a));
        }

        if let Some(a) = tx.append_request_body(b"comment=hello+world")? {
            return Ok(Some(a));
        }
        if let Some(a) = tx.process_request_body()? {
            return Ok(Some(a));
        }

        tx.add_response_header(b"Content-Type", b"text/html")?;
        if let Some(a) = tx.process_response_headers(200, "HTTP/1.1")? {
            return Ok(Some(a));
        }
        if let Some(a) = tx.append_response_body(b"<html>ok</html>")? {
            return Ok(Some(a));
        }
        tx.process_response_body()
    })();

    // Always run phase 5, blocked or not: it is what flushes the audit log.
    tx.process_logging()?;
    outcome
}
