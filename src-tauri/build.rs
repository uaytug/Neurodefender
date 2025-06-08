fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tauri build
    tauri_build::build();

    // Configure vergen to emit all build, cargo, rustc, and sysinfo instructions.
    vergen::EmitBuilder::builder()
        .all_build()
        .all_cargo()
        .all_rustc()
        .all_sysinfo()
        .emit()?;
    Ok(())
}
