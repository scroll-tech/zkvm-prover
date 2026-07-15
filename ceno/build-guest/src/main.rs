use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use tracing::info;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum BuildMode {
    #[default]
    Auto,
    Force,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long, default_value = "releases/dev/ceno")]
    output_dir: PathBuf,

    #[arg(long, value_delimiter = ',', default_value = "chunk,batch,bundle")]
    projects: Vec<String>,

    #[arg(long, value_enum, default_value = "auto")]
    mode: BuildMode,

    /// Path to cargo-ceno. The installed `cargo ceno` subcommand is `cargo-ceno`.
    #[arg(long, default_value = "cargo-ceno")]
    cargo_ceno: String,

    /// Optional Rust toolchain selector passed to cargo-ceno, e.g. `+nightly`.
    #[arg(long, env = "CENO_RUST_TOOLCHAIN")]
    toolchain: Option<String>,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.output_dir)?;

    for project in &args.projects {
        info!("building Ceno guest: {project}");
        let elf_path = build_ceno_program(&args, project)?;
        info!("ELF written to: {}", elf_path.display());
    }

    Ok(())
}

fn build_ceno_program(args: &Args, project: &str) -> eyre::Result<PathBuf> {
    let out_dir = args.output_dir.join(project);
    std::fs::create_dir_all(&out_dir)?;
    let dst = out_dir.join("app");

    if matches!(args.mode, BuildMode::Auto) && dst.exists() {
        info!("ELF already exists at {}, skipping build", dst.display());
        return Ok(dst);
    }

    let package = format!("scroll-zkvm-ceno-{project}-circuit");
    let manifest = Path::new("Cargo.toml");
    if !manifest.exists() {
        eyre::bail!("run build-guest-ceno from the ceno workspace root");
    }

    let mut cmd = Command::new(&args.cargo_ceno);
    cmd.arg("ceno");
    if let Some(toolchain) = &args.toolchain {
        cmd.arg(toolchain);
    }
    cmd.arg("build")
        .arg("--release")
        .arg("-p")
        .arg(&package)
        .arg("--bin")
        .arg(project)
        .arg("--target-dir")
        .arg("target");

    let status = cmd
        .status()
        .map_err(|e| eyre::eyre!("failed to spawn `{}`: {e}", args.cargo_ceno))?;
    if !status.success() {
        eyre::bail!("`cargo ceno build` failed for {project} (status {status})");
    }

    let built = Path::new("target")
        .join("riscv32im-ceno-zkvm-elf")
        .join("release")
        .join(project);
    if !built.exists() {
        eyre::bail!("expected Ceno ELF not found at {}", built.display());
    }

    std::fs::copy(&built, &dst).map_err(|e| {
        eyre::eyre!(
            "failed to copy {} -> {}: {e}",
            built.display(),
            dst.display()
        )
    })?;

    Ok(dst)
}
