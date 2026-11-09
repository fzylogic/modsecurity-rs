# modsecurity-rs

Safe Rust bindings to [libmodsecurity v3][upstream] — the engine behind
ModSecurity and the OWASP Core Rule Set.

The crate is two layers:

* `modsecurity::ffi` — hand-written declarations of the C API. The only module
  with `extern` blocks. You should not need it.
* everything else — a safe wrapper in which the compiler enforces the rules the
  C API only documents.

## Requirements

`libmodsecurity` 3.x and its headers:

```sh
# Debian / Ubuntu
sudo apt install libmodsecurity3 libmodsecurity-dev
# Fedora / RHEL
sudo dnf install mod_security libmodsecurity-devel
# macOS
brew install libmodsecurity
```

The build script links `-lmodsecurity` and honours three environment variables:

| Variable | Effect |
| --- | --- |
| `MODSECURITY_LIB_DIR` | extra library search path |
| `MODSECURITY_LIB_NAME` | link name, default `modsecurity` |
| `MODSECURITY_STATIC=1` | link statically, pulling in the C++ runtime |

## Usage

```rust
use modsecurity::{ModSecurity, Rules, Transaction};

// Once per process, shared across threads.
let mut ms = ModSecurity::new()?.with_connector_info("my-proxy/1.0")?;
ms.set_log_callback(|msg: &[u8]| {
    eprintln!("[modsec] {}", String::from_utf8_lossy(msg));
});

let mut rules = Rules::new()?;
rules.add_file("/etc/modsecurity.d/include.conf")?;

// Once per request.
let mut tx = Transaction::with_id(&ms, &rules, "req-0001")?;
tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443)?;
tx.process_uri("/search?q=%3Cscript%3E", "GET", "1.1")?;
tx.add_request_header(b"Host", b"example.com")?;

if let Some(action) = tx.process_request_headers()? {
    eprintln!("blocked: HTTP {} — {:?}", action.status, action.log_message());
}
tx.process_logging()?;
```

Each phase method returns `Ok(Some(intervention))` when a rule asked for a
disruptive action. Feed the request and response through in order
(`connection` → `uri` → request headers → request body → response headers →
response body → logging), and call `process_logging` at the end of every
transaction — that is what flushes the audit log.

There is a worked example:

```sh
cargo run --example inspect_request -- "/search?q=%3Cscript%3E"
cargo run --example inspect_request -- /index.html /etc/modsecurity.d/include.conf
```

## What the wrapper guarantees

* **Ordering.** A `Transaction` borrows the `ModSecurity` handle and the `Rules`
  set, so neither can be dropped while a transaction is alive. The
  use-after-free the C API invites is a compile error here.
* **No leaks.** Rule sets and transactions are released by `Drop`; the
  `strdup`ed strings libmodsecurity returns in interventions and parser errors
  are copied into Rust `String`s and freed immediately.
* **No aliasing.** Every call that mutates C++ state takes `&mut self`.
* **No unwinding into C++.** Log callbacks run inside `catch_unwind`.
* **Arbitrary bytes.** Header names and values are passed with explicit
  lengths, so they may hold any byte, NUL included. Arguments that must be C
  strings report interior NULs as `Error::InteriorNul` instead of panicking.

Every `unsafe` block carries a `SAFETY:` comment naming the invariant it relies
on, `unsafe_op_in_unsafe_fn` is denied crate-wide, and `unsafe` is confined to
the five modules that touch the C API: `ffi`, `intervention`, `modsecurity`,
`rules`, `transaction`. The public API exposes exactly one `unsafe` function,
`ModSecurity::shutdown`, which exists only so that a program can run the engine
destructor deliberately.

## Working around libmodsecurity

Two upstream behaviours cannot be wrapped literally without handing safe Rust a
way to corrupt memory. Both were found by the test suite in this repository,
against libmodsecurity 3.0.12.

**The engine destructor is process-global.** `~ModSecurity()` calls libxml2's
`xmlCleanupParser()`, which frees state shared by every libxml2 user in the
program. Destroying one engine while another engine, another thread, or an
unrelated XML-using crate is running is a use-after-free — reproducibly, a
`double free or corruption` abort. So this crate creates exactly one engine per
process, lazily, and never destroys it; `ModSecurity` is a cheap handle to it.
Dropping a handle is free and disturbs nothing.

Two things follow, and only matter if you hold several handles at once:
`set_connector_info` writes shared state (last call wins), while
`set_log_callback` is per handle — a transaction reports to the callback of the
handle that created it. `ModSecurity::shutdown` exists as an `unsafe` escape
hatch for programs that must satisfy a leak checker at exit.

**The SecLang parser has global state.** Parsing two rule sets concurrently
interleaves their diagnostics and corrupts the heap. `Rules` serialises
construction, parsing and destruction behind one process-wide lock. Evaluation
is untouched: concurrent request inspection against a shared rule set, the hot
path and the model upstream's own connectors use, stays lock-free.

## Logging versus interventions

libmodsecurity splits rule output in two, which is easy to misread:

| Match | Reported as |
| --- | --- |
| disruptive (`deny`, `drop`, `redirect`, …) | an `Intervention` returned by the phase method; message in `Intervention::log` |
| non-disruptive (`pass` with `log`) | the callback registered with `set_log_callback` |

A disruptive match never reaches the log callback. Handle both to see
everything.

## Known gaps

* `msc_get_response_body` is deliberately not wrapped: upstream implements it as
  `return m_responseBody.str().c_str();`, returning a pointer into a `std::string`
  temporary that is destroyed before the call returns. `Transaction::response_body_length`
  is provided; libmodsecurity v3 never rewrites a body, so the caller already
  holds the bytes it supplied. The raw declaration remains in `modsecurity::ffi`.
* `Transaction` is `Send` but not `Sync` — move it between threads freely, but
  one thread at a time, which `&mut self` on every method already enforces.

## Testing

```sh
cargo test                                          # 18 integration tests, no dependencies
cargo clippy --all-targets
cargo test --release -- --ignored --nocapture       # resident-memory leak check
scripts/valgrind-test.sh                            # the whole suite under Valgrind
```

The suite covers the phase state machine, request and response body inspection,
interventions (deny and redirect), per-handle log callbacks, binary header
values, error reporting, panics in callbacks, and concurrent parsing and
evaluation across threads.

### Memory checking with Valgrind

A safe wrapper around a C++ library is only as good as its heap discipline, so
memory correctness is checked two ways, both driven by `scripts/valgrind-test.sh`.

**From outside**, that script points cargo's test runner at
`scripts/valgrind-runner.sh`, so every test binary — not just the memory
tests — runs under Memcheck. A definite or indirect leak, an invalid access, a
double free or a read of uninitialised memory exits 99 and fails the run.
"Still reachable" is not an error: the engine is a deliberate process-wide
singleton (see above). Pass anything you like through to cargo:

```sh
scripts/valgrind-test.sh                      # everything
scripts/valgrind-test.sh --test memcheck      # just the memory tests
scripts/valgrind-test.sh -- --nocapture foo   # harness arguments after --
```

**From inside**, `tests/memcheck.rs` uses [crabgrind] to call Valgrind's
client-request interface from within the test process. That buys something an
outside-in run cannot do: it takes leak and error counts *around a specific
workload*, so one-time start-up allocations — the engine singleton included —
cancel out and whatever remains is attributable to the code under test. The
tests bracket 500 disrupted transactions, 100 transactions carrying 16 KiB
bodies, 25 rule-set build/merge/error cycles and 200 trips through the log
trampoline, and assert the delta is zero bytes.

Both layers were verified to fail, not just to pass: dropping the `free` in
`Intervention::take_cstring` makes the in-process check report
`500 disrupted transactions leaked 248955 bytes` and Valgrind exit 99, and
freeing twice there is caught as `Invalid free()` by the error-count test.

crabgrind is an **optional** dependency behind the `valgrind` feature, which
exists only to build that test target — it needs the Valgrind headers and
libclang, so plain `cargo test` neither builds nor requires it, and the library
keeps its empty dependency list. The script enables the feature itself.

Without Valgrind, every client request is a silent no-op, so the memory tests
report that they were skipped and pass. `scripts/valgrind-test.sh` sets
`MODSEC_REQUIRE_VALGRIND=1`, which turns that skip into a failure so the entry
point cannot pass vacuously.

`valgrind.supp` holds the suppressions. There is exactly one: a `std::thread`
handle the Rust test harness allocates for the main thread and parks in a
thread-local Memcheck cannot follow. Nothing is suppressed for libmodsecurity —
3.0.12 reports no definite or indirect leaks under this suite. The file carries
a commented template if another platform needs one.

[crabgrind]: https://github.com/2dav/crabgrind

## License

Apache-2.0, matching upstream ModSecurity.

[upstream]: https://github.com/owasp-modsecurity/ModSecurity
