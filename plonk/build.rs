fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if rustc_version::version_meta().unwrap().channel == rustc_version::Channel::Nightly {
        println!("cargo:rustc-cfg=nightly");
    }
}
