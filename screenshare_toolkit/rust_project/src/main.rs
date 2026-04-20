fn main() {
    if let Err(error) = rust_project::app::run() {
        eprintln!("Fatal error: {error:#}");
        std::process::exit(1);
    }
}
