extern crate bindgen;

use std::env;
// use std::path::PathBuf;

fn main() {
    //only for cargo run, shoud export the path of libclient_bindings.so if run binary
    println!("cargo:rustc-env=LD_LIBRARY_PATH=./lib");
    println!("cargo:rustc-env=DYLD_FALLBACK_LIBRARY_PATH=./lib");

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=./lib");

    // Tell cargo to tell rustc to link the client_bindings (libclient_bindings.so)
    println!("cargo:rustc-link-lib=client_bindings");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=./lib/libclient_bindings.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("./lib/libclient_bindings.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    //let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        //.write_to_file(out_path.join("bindings.rs"))
        .write_to_file("./bindings.rs")
        .expect("Couldn't write bindings!");
}
