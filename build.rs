fn main() {
    // Embed icon and manifest (requireAdministrator).
    let empty: [&str; 0] = [];
    embed_resource::compile("internaldumper.rc", &empty);
}
