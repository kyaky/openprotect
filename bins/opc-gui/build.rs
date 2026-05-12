//! Embed the Windows manifest into opc-gui.exe on Windows builds.
//!
//! The manifest forces UAC elevation: opc.exe (spawned as a child)
//! needs administrator rights to create the Wintun adapter, install
//! routes via `netsh`/`route.exe`, and write NRPT entries to HKLM.
//! Without elevation, opc.exe blocks in the Wintun driver call and
//! the GUI can't even kill it (the process is in an uninterruptible
//! kernel-mode wait — `taskkill /F` is a no-op there).
//!
//! Embedding the manifest into the PE means Windows reads it before
//! the process starts, fires the UAC prompt up front, and the
//! elevation propagates to every child opc.exe.

fn main() {
    #[cfg(windows)]
    embed_manifest::embed_manifest_file("opc-gui.manifest")
        .expect("embed opc-gui.manifest into the executable");

    println!("cargo:rerun-if-changed=opc-gui.manifest");
    println!("cargo:rerun-if-changed=build.rs");
}
