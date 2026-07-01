//! Build ZisK guest ELFs by driving `cargo-zisk build`, then copy each ELF to
//! `releases/dev/zisk/{circuit}/app` (mirrors `sp1/build-guest`).
//!
//! `cargo-zisk build --release` emits the ELF at
//! `<circuit-crate>/target/elf/riscv64ima-zisk-zkvm-elf/release/<bin>`; we copy it to a
//! stable release path the host/benchmark loads.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use tracing::info;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum BuildMode {
    /// Rebuild only if the ELF is missing.
    #[default]
    Auto,
    /// Always rebuild the ELF.
    Force,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, default_value = "circuits")]
    circuits_dir: PathBuf,

    #[arg(long, default_value = "releases/dev/zisk")]
    output_dir: PathBuf,

    #[arg(long, value_delimiter = ',', default_value = "chunk,batch,bundle")]
    projects: Vec<String>,

    #[arg(long, value_enum, default_value = "auto")]
    mode: BuildMode,

    /// Path to the `cargo-zisk` binary (defaults to `cargo-zisk` on PATH).
    #[arg(long, default_value = "cargo-zisk")]
    cargo_zisk: String,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    std::fs::create_dir_all(&args.output_dir)?;

    for project in &args.projects {
        info!("building ZisK guest: {project}");
        let program_dir = args.circuits_dir.join(format!("{project}-circuit"));
        let elf_path = build_zisk_program(&args, &program_dir, project)?;
        info!("ELF written to: {}", elf_path.display());
    }

    Ok(())
}

fn build_zisk_program(args: &Args, program_dir: &Path, project: &str) -> eyre::Result<PathBuf> {
    let out_dir = args.output_dir.join(project);
    std::fs::create_dir_all(&out_dir)?;
    let dst = out_dir.join("app");

    if matches!(args.mode, BuildMode::Auto) && dst.exists() {
        info!("ELF already exists at {}, skipping build", dst.display());
        return Ok(dst);
    }

    if !program_dir.exists() {
        eyre::bail!("circuit crate not found: {}", program_dir.display());
    }

    // `cargo-zisk build --release` inside the circuit crate.
    //
    // NOTE: `cargo-zisk build` sets the `RUSTFLAGS` env var itself (to the trimmed value
    // of any inherited `RUSTFLAGS`), which makes cargo IGNORE the `[target.*].rustflags`
    // in `.cargo/config.toml`. So the `getrandom_backend="custom"` cfg the chunk guest
    // needs (getrandom 0.3.x, pulled by the sbv/revm graph) must be injected here via the
    // env, otherwise it never reaches the build. We preserve any inherited RUSTFLAGS.
    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    if !rustflags.contains("getrandom_backend") {
        if !rustflags.is_empty() {
            rustflags.push(' ');
        }
        rustflags.push_str("--cfg getrandom_backend=\"custom\"");
    }
    let status = Command::new(&args.cargo_zisk)
        .arg("build")
        .arg("--release")
        .env("RUSTFLAGS", &rustflags)
        .current_dir(program_dir)
        .status()
        .map_err(|e| eyre::eyre!("failed to spawn `{} build`: {e}", args.cargo_zisk))?;
    if !status.success() {
        eyre::bail!("`cargo-zisk build` failed for {project} (status {status})");
    }

    let built = program_dir
        .join("target/elf/riscv64ima-zisk-zkvm-elf/release")
        .join(project);
    if !built.exists() {
        eyre::bail!("expected ELF not found at {}", built.display());
    }

    std::fs::copy(&built, &dst)
        .map_err(|e| eyre::eyre!("failed to copy {} -> {}: {e}", built.display(), dst.display()))?;

    Ok(dst)
}
