//! Locates and links `libmodsecurity` (ModSecurity v3).
//!
//! Override discovery with:
//!   * `MODSECURITY_LIB_DIR`  - directory containing `libmodsecurity.so` / `.a`
//!   * `MODSECURITY_STATIC=1` - link statically (also links the C++ runtime)
//!   * `MODSECURITY_LIB_NAME` - link name, defaults to `modsecurity`

use std::path::Path;

fn main() {
    for var in [
        "MODSECURITY_LIB_DIR",
        "MODSECURITY_STATIC",
        "MODSECURITY_LIB_NAME",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-changed=build.rs");

    let name = std::env::var("MODSECURITY_LIB_NAME").unwrap_or_else(|_| "modsecurity".to_string());
    let static_link = matches!(
        std::env::var("MODSECURITY_STATIC").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );

    if let Ok(dir) = std::env::var("MODSECURITY_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
    } else {
        // Common install prefixes that are not always on the default search path.
        for dir in [
            "/usr/local/lib",
            "/opt/homebrew/lib",
            "/usr/local/modsecurity/lib",
        ] {
            if Path::new(dir).is_dir() {
                println!("cargo:rustc-link-search=native={dir}");
            }
        }
    }

    if static_link {
        println!("cargo:rustc-link-lib=static={name}");
        // libmodsecurity is C++; a static link must pull in the C++ runtime and
        // its usual transitive dependencies.
        let cxx = if cfg!(target_os = "macos") {
            "c++"
        } else {
            "stdc++"
        };
        println!("cargo:rustc-link-lib=dylib={cxx}");
        for lib in ["pcre", "xml2", "yajl"] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    } else {
        println!("cargo:rustc-link-lib=dylib={name}");
    }
}
