fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=csrc/progress_shim.c");
    println!("cargo:rerun-if-env-changed=OPENCONNECT_DIR");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // On Windows, libopenconnect must be built manually (vcpkg, MSYS2,
    // or from source). Set OPENCONNECT_DIR to point at the install prefix
    // (the directory containing include/ and lib/).
    //
    // On Unix, pkg-config finds it automatically.
    let lib = if target_os == "windows" {
        match std::env::var("OPENCONNECT_DIR") {
            Ok(dir) => {
                let dir = std::path::Path::new(&dir);
                println!(
                    "cargo:rustc-link-search=native={}",
                    dir.join("lib").display()
                );
                println!("cargo:rustc-link-lib=openconnect");
                // Return include path for bindgen.
                Some(vec![dir.join("include")])
            }
            Err(_) => {
                println!(
                    "cargo:warning=OPENCONNECT_DIR not set — skipping FFI bindings. \
                     The tunnel stub will be used. To build with full tunnel support, \
                     install libopenconnect and set OPENCONNECT_DIR=<prefix>."
                );
                std::fs::write(
                    out_dir.join("bindings.rs"),
                    "// openconnect bindings unavailable — OPENCONNECT_DIR not set\n",
                )
                .ok();
                return;
            }
        }
    } else {
        // Unix: use pkg-config.
        match pkg_config::probe_library("openconnect") {
            Ok(lib) => Some(lib.include_paths),
            Err(e) => {
                println!(
                    "cargo:warning=libopenconnect not found ({e}). \
                     Install it with: apt install libopenconnect-dev (Debian/Ubuntu) \
                     or dnf install openconnect-devel (Fedora). \
                     Skipping FFI binding generation."
                );
                std::fs::write(
                    out_dir.join("bindings.rs"),
                    "// openconnect bindings unavailable — libopenconnect-dev not installed\n",
                )
                .ok();
                return;
            }
        }
    };

    // Generate Rust bindings with bindgen.
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("openconnect_.*")
        .allowlist_type("openconnect_.*")
        .allowlist_type("oc_.*")
        .allowlist_var("OC_.*")
        .allowlist_var("PRG_.*");

    if let Some(include_paths) = lib {
        for path in &include_paths {
            builder = builder.clang_arg(format!("-I{}", path.display()));
        }
    }

    let bindings = builder
        .generate()
        .expect("failed to generate openconnect bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    // Compile the C variadic trampoline for openconnect's progress callback.
    if target_os != "windows" {
        // The C shim is Unix-only for now (uses va_list + vsnprintf).
        // Windows support would need the same shim compiled with MSVC.
        cc::Build::new()
            .file("csrc/progress_shim.c")
            .warnings(true)
            .compile("pangolin_progress_shim");
    }
}
