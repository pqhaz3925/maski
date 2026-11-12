// With the `ffi` feature: (re)generate include/maski.h from src/ffi.rs.
fn main() {
    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    #[cfg(feature = "ffi")]
    {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let cfg = cbindgen::Config::from_file(format!("{dir}/cbindgen.toml")).expect("cbindgen.toml");
        cbindgen::Builder::new()
            .with_config(cfg)
            .with_src(format!("{dir}/src/ffi.rs"))
            .generate()
            .expect("cbindgen")
            .write_to_file(format!("{dir}/include/maski.h"));
    }
}
