fn main() {
    // gp-openconnect-sys (links = "openconnect") emits
    // `cargo:has_bindings=1` when real FFI bindings were generated.
    // Cargo surfaces that as `DEP_OPENCONNECT_HAS_BINDINGS` here.
    if std::env::var("DEP_OPENCONNECT_HAS_BINDINGS").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=has_openconnect");
    }
}
