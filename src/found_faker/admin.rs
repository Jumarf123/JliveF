pub fn is_elevated() -> bool {
    is_elevated::is_elevated()
}

pub fn ensure_admin() {
    if !is_elevated() {
        eprintln!(
            "This tool must be run as Administrator. Please restart it with elevated privileges."
        );
        std::process::exit(1);
    }
}
