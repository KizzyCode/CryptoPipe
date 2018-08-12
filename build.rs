extern crate pkg_config;

const LIBSODIUM_VERSION: &str = "1.0.16";

fn link_libsodium() {
	let libsodium = pkg_config::Config::new().statik(true).probe("libsodium").unwrap();
	assert_eq!(libsodium.version, LIBSODIUM_VERSION, "Invalid libsodium-version ({} vs. {})", libsodium.version, LIBSODIUM_VERSION);
}

fn main() {
	link_libsodium()
}