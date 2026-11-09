//! Safe Rust bindings to [libmodsecurity v3], the engine behind ModSecurity and
//! the OWASP Core Rule Set.
//!
//! The crate is split in two:
//!
//! * [`ffi`] — hand-written declarations of libmodsecurity's C API. Calling it
//!   is `unsafe` and you should not need to.
//! * everything else — a safe wrapper in which the compiler enforces the rules
//!   the C API only documents.
//!
//! # What the wrapper guarantees
//!
//! * **Ordering.** A [`Transaction`] borrows the [`ModSecurity`] handle and the
//!   [`Rules`] set, so neither can be dropped while a transaction is alive —
//!   the use-after-free the C API invites is a compile error here.
//! * **No leaks.** Rule sets and transactions are released by `Drop`. The
//!   `strdup`ed strings libmodsecurity hands back in interventions and parser
//!   errors are copied into Rust `String`s and freed immediately.
//! * **No aliasing.** Every call that mutates C++ state takes `&mut self`.
//! * **No unwinding into C++.** Log callbacks are wrapped in
//!   [`catch_unwind`](std::panic::catch_unwind).
//! * **Arbitrary bytes.** Header names and values are passed with explicit
//!   lengths, so they may contain any byte. Arguments that must be C strings
//!   report interior NULs as [`Error::InteriorNul`] rather than panicking.
//!
//! Every `unsafe` block carries a `SAFETY:` comment naming the invariant it
//! relies on, `unsafe_op_in_unsafe_fn` is denied crate-wide, and `unsafe` is
//! confined to the five modules that touch the C API: `ffi`, `intervention`,
//! `modsecurity`, `rules` and `transaction`. The public API exposes exactly one
//! `unsafe` function, [`ModSecurity::shutdown`], which exists only so that a
//! program can run the engine destructor deliberately.
//!
//! # Working around libmodsecurity
//!
//! Two upstream behaviours make the C API unsound to wrap literally. Both are
//! reachable from ordinary safe code, so the crate designs around them rather
//! than documenting them as caveats.
//!
//! * **The engine destructor is process-global.** `~ModSecurity()` calls
//!   libxml2's `xmlCleanupParser()`, which frees state shared by every libxml2
//!   user in the program. Destroying one engine while another — or another
//!   thread, or an unrelated XML-using crate — is running is a use-after-free.
//!   This crate therefore creates exactly one engine per process, lazily, and
//!   never destroys it; [`ModSecurity`] is a handle to it. See that type for
//!   what follows from this.
//! * **The SecLang parser has global state.** Parsing two rule sets at once
//!   interleaves their diagnostics and corrupts the heap. [`Rules`] serialises
//!   construction, parsing and destruction behind one process-wide lock.
//!   Evaluation stays lock-free, so concurrent request inspection — the hot
//!   path, and the model libmodsecurity's own connectors use — is unaffected.
//!
//! # What it cannot guarantee
//!
//! libmodsecurity is a large C++ library and a segfault or leak inside it is
//! still possible; `Send`/`Sync` here assert that its documented threading
//! model (one engine and one rule set shared by many concurrent transactions)
//! holds. One upstream accessor, `msc_get_response_body`, returns a pointer
//! into a destroyed temporary and is deliberately left unwrapped — see
//! [`Transaction::response_body_length`].
//!
//! # Logging and interventions
//!
//! libmodsecurity splits rule output in two, which is easy to misread:
//!
//! * a **disruptive** match (`deny`, `drop`, `redirect`, …) is reported as an
//!   [`Intervention`] returned from the phase method, and its message is in
//!   [`Intervention::log`] — it does *not* reach the log callback;
//! * a **non-disruptive** match (`pass` with `log`) is reported only through
//!   the callback registered with
//!   [`ModSecurity::set_log_callback`].
//!
//! Register a callback *and* handle interventions to see everything.
//!
//! # Example
//!
//! ```no_run
//! use modsecurity::{ModSecurity, Rules, Transaction};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let ms = ModSecurity::new()?.with_connector_info("example/1.0")?;
//!
//! let mut rules = Rules::new()?;
//! rules.add_plain(
//!     r#"
//!     SecRuleEngine On
//!     SecRule ARGS:q "@contains <script>" "id:1001,phase:1,deny,status:403,msg:'xss'"
//!     "#,
//! )?;
//!
//! let mut tx = Transaction::new(&ms, &rules)?;
//! tx.process_connection("203.0.113.9", 51234, "198.51.100.1", 443)?;
//! tx.process_uri("/search?q=%3Cscript%3E", "GET", "1.1")?;
//! tx.add_request_header(b"Host", b"example.com")?;
//!
//! match tx.process_request_headers()? {
//!     Some(action) => println!("block with HTTP {}", action.status),
//!     None => println!("allow"),
//! }
//! tx.process_logging()?;
//! # Ok(()) }
//! ```
//!
//! # Linking
//!
//! `libmodsecurity` (3.x) and its headers must be installed. The build script
//! links `-lmodsecurity` and honours `MODSECURITY_LIB_DIR`,
//! `MODSECURITY_LIB_NAME` and `MODSECURITY_STATIC`.
//!
//! [libmodsecurity v3]: https://github.com/owasp-modsecurity/ModSecurity

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    unreachable_pub,
    clippy::undocumented_unsafe_blocks,
    clippy::must_use_candidate
)]

pub mod ffi;

mod error;
mod intervention;
mod modsecurity;
mod rules;
mod transaction;

pub use crate::error::{Error, Result};
pub use crate::intervention::Intervention;
pub use crate::modsecurity::{LogCallback, ModSecurity};
pub use crate::rules::Rules;
pub use crate::transaction::Transaction;
