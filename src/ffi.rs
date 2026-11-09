//! Raw, hand-written declarations for the libmodsecurity v3 C API.
//!
//! This is the *only* module in the crate that declares foreign functions.
//! Everything in here is `unsafe` to call; the rest of the crate exists to make
//! calling it unnecessary.
//!
//! The declarations mirror the `extern "C"` blocks of `modsecurity/modsecurity.h`,
//! `modsecurity/rules_set.h`, `modsecurity/transaction.h` and
//! `modsecurity/intervention.h` as of ModSecurity 3.0.x.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::marker::{PhantomData, PhantomPinned};

/// Opaque `modsecurity::ModSecurity`.
#[repr(C)]
#[derive(Debug)]
pub struct ModSecurity {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque `modsecurity::RulesSet`.
#[repr(C)]
#[derive(Debug)]
pub struct RulesSet {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque `modsecurity::Transaction`.
#[repr(C)]
#[derive(Debug)]
pub struct Transaction {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `modsecurity::ModSecurityIntervention`, from `intervention.h`.
///
/// `url` and `log` are allocated by libmodsecurity with `strdup` and must be
/// released by the caller with [`free`].
#[repr(C)]
#[derive(Debug)]
pub struct ModSecurityIntervention {
    /// HTTP status code the server should return.
    pub status: c_int,
    /// Milliseconds the server should stall for (`pause` action).
    pub pause: c_int,
    /// `strdup`ed redirect target, or `NULL`.
    pub url: *mut c_char,
    /// `strdup`ed log line for the rule that fired, or `NULL`.
    pub log: *mut c_char,
    /// Non-zero when the request must actually be disrupted.
    pub disruptive: c_int,
}

impl ModSecurityIntervention {
    /// The zero value libmodsecurity expects an intervention out-parameter to
    /// hold before it is passed to `msc_intervention`.
    ///
    /// `msc_intervention` only writes to the struct when the transaction has a
    /// disruptive action pending, so every field must be initialised first.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            status: 200,
            pause: 0,
            url: core::ptr::null_mut(),
            log: core::ptr::null_mut(),
            disruptive: 0,
        }
    }
}

/// `typedef void (*ModSecLogCb)(void *, const void *);`
///
/// The second argument is a NUL-terminated `const char *` unless additional
/// log properties were requested (which this crate does not do).
pub type ModSecLogCb = Option<unsafe extern "C" fn(data: *mut c_void, msg: *const c_void)>;

unsafe extern "C" {
    // --- modsecurity.h -----------------------------------------------------
    /// Creates a new ModSecurity engine. Returns `NULL` on failure.
    pub fn msc_init() -> *mut ModSecurity;
    /// Returns the engine's self-description, owned by the engine.
    pub fn msc_who_am_i(msc: *mut ModSecurity) -> *const c_char;
    /// Records the host connector's name and version.
    pub fn msc_set_connector_info(msc: *mut ModSecurity, connector: *const c_char);
    /// Installs the callback invoked for every log entry.
    pub fn msc_set_log_cb(msc: *mut ModSecurity, cb: ModSecLogCb);
    /// Destroys an engine created by [`msc_init`].
    pub fn msc_cleanup(msc: *mut ModSecurity);

    // --- rules_set.h -------------------------------------------------------
    /// Creates an empty rules set. Returns `NULL` on failure.
    pub fn msc_create_rules_set() -> *mut RulesSet;
    /// Prints the parsed rules to standard output.
    pub fn msc_rules_dump(rules: *mut RulesSet);
    /// Copies the rules of `rules_from` into `rules_dst`.
    ///
    /// Returns the number of rules added, or `-1` after setting `*error` to a
    /// `strdup`ed diagnostic the caller must [`free`].
    pub fn msc_rules_merge(
        rules_dst: *mut RulesSet,
        rules_from: *mut RulesSet,
        error: *mut *const c_char,
    ) -> c_int;
    /// Downloads and parses a remote rules file.
    ///
    /// Returns the number of rules added, or `-1` after setting `*error` to a
    /// `strdup`ed diagnostic the caller must [`free`].
    pub fn msc_rules_add_remote(
        rules: *mut RulesSet,
        key: *const c_char,
        uri: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    /// Parses a rules file.
    ///
    /// Returns the number of rules added, or `-1` after setting `*error` to a
    /// `strdup`ed diagnostic the caller must [`free`].
    pub fn msc_rules_add_file(
        rules: *mut RulesSet,
        file: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    /// Parses inline SecLang rule text.
    ///
    /// Returns the number of rules added, or `-1` after setting `*error` to a
    /// `strdup`ed diagnostic the caller must [`free`].
    pub fn msc_rules_add(
        rules: *mut RulesSet,
        plain_rules: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    /// Destroys a rules set created by [`msc_create_rules_set`].
    pub fn msc_rules_cleanup(rules: *mut RulesSet) -> c_int;

    // --- transaction.h -----------------------------------------------------
    /// Starts a transaction with a generated id. Returns `NULL` on failure.
    ///
    /// `log_cb_data` is handed back verbatim to the engine's log callback.
    pub fn msc_new_transaction(
        ms: *mut ModSecurity,
        rules: *mut RulesSet,
        log_cb_data: *mut c_void,
    ) -> *mut Transaction;
    /// Starts a transaction with a caller-supplied id, which is copied.
    pub fn msc_new_transaction_with_id(
        ms: *mut ModSecurity,
        rules: *mut RulesSet,
        id: *mut c_char,
        log_cb_data: *mut c_void,
    ) -> *mut Transaction;
    /// Records the connection endpoints (phase 0).
    pub fn msc_process_connection(
        transaction: *mut Transaction,
        client: *const c_char,
        c_port: c_int,
        server: *const c_char,
        s_port: c_int,
    ) -> c_int;
    /// Records the request line and parses the query string into `ARGS`.
    ///
    /// Despite its name, `protocol` is assigned to `REQUEST_METHOD`.
    pub fn msc_process_uri(
        transaction: *mut Transaction,
        uri: *const c_char,
        protocol: *const c_char,
        http_version: *const c_char,
    ) -> c_int;
    /// Evaluates phase 1 (`REQUEST_HEADERS`).
    pub fn msc_process_request_headers(transaction: *mut Transaction) -> c_int;
    /// Adds a request header given as explicit byte ranges.
    pub fn msc_add_n_request_header(
        transaction: *mut Transaction,
        key: *const c_uchar,
        len_key: usize,
        value: *const c_uchar,
        len_value: usize,
    ) -> c_int;
    /// Evaluates phase 2 (`REQUEST_BODY`).
    pub fn msc_process_request_body(transaction: *mut Transaction) -> c_int;
    /// Appends bytes to the buffered request body.
    pub fn msc_append_request_body(
        transaction: *mut Transaction,
        body: *const c_uchar,
        size: usize,
    ) -> c_int;
    /// Uses a file's contents as the request body.
    pub fn msc_request_body_from_file(transaction: *mut Transaction, path: *const c_char) -> c_int;
    /// Evaluates phase 3 (`RESPONSE_HEADERS`).
    pub fn msc_process_response_headers(
        transaction: *mut Transaction,
        code: c_int,
        protocol: *const c_char,
    ) -> c_int;
    /// Adds a response header given as explicit byte ranges.
    pub fn msc_add_n_response_header(
        transaction: *mut Transaction,
        key: *const c_uchar,
        len_key: usize,
        value: *const c_uchar,
        len_value: usize,
    ) -> c_int;
    /// Evaluates phase 4 (`RESPONSE_BODY`).
    pub fn msc_process_response_body(transaction: *mut Transaction) -> c_int;
    /// Appends bytes to the buffered response body.
    pub fn msc_append_response_body(
        transaction: *mut Transaction,
        body: *const c_uchar,
        size: usize,
    ) -> c_int;
    /// # Warning
    ///
    /// Upstream implements this as `return m_responseBody.str().c_str();`,
    /// which returns a pointer into a `std::string` temporary that is destroyed
    /// before the function returns. The crate therefore does not wrap it.
    pub fn msc_get_response_body(transaction: *mut Transaction) -> *const c_char;
    /// Returns the number of buffered response body bytes.
    pub fn msc_get_response_body_length(transaction: *mut Transaction) -> usize;
    /// Returns the number of buffered request body bytes.
    pub fn msc_get_request_body_length(transaction: *mut Transaction) -> usize;
    /// Records the status code the server actually produced.
    pub fn msc_update_status_code(transaction: *mut Transaction, status: c_int) -> c_int;
    /// Takes the pending disruptive action, if any.
    ///
    /// Returns non-zero when `it` was filled in. `it` must be fully
    /// initialised beforehand (see [`ModSecurityIntervention::zeroed`]), and
    /// its `url` and `log` strings become the caller's to [`free`].
    pub fn msc_intervention(
        transaction: *mut Transaction,
        it: *mut ModSecurityIntervention,
    ) -> c_int;
    /// Evaluates phase 5 (`LOGGING`) and flushes the audit log.
    pub fn msc_process_logging(transaction: *mut Transaction) -> c_int;
    /// Destroys a transaction created by [`msc_new_transaction`].
    pub fn msc_transaction_cleanup(transaction: *mut Transaction);

    // --- libc --------------------------------------------------------------
    /// Releases the `strdup`-allocated strings handed back by the API above.
    ///
    /// Declared here rather than taken from the `libc` crate so that this crate
    /// has no dependencies; libmodsecurity and this process share one libc.
    pub fn free(ptr: *mut c_void);
}
