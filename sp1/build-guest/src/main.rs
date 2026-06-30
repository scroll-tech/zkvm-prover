use std::path::{Path, PathBuf};

use clap::Parser;
use sp1_build::build_program_with_args;
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

    #[arg(long, default_value = "releases/dev/sp1")]
    output_dir: PathBuf,

    #[arg(long, value_delimiter = ',', default_value = "chunk,batch,bundle")]
    projects: Vec<String>,

    #[arg(long, value_enum, default_value = "auto")]
    mode: BuildMode,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    std::fs::create_dir_all(&args.output_dir)?;

    for project in &args.projects {
        info!("building SP1 guest: {project}");
        let program_dir = args.circuits_dir.join(format!("{project}-circuit"));
        let elf_path = build_sp1_program(&program_dir, &args.output_dir, project, &args.mode)?;
        info!("ELF written to: {}", elf_path.display());
    }

    Ok(())
}

fn build_sp1_program(
    program_dir: &Path,
    output_dir: &Path,
    project: &str,
    mode: &BuildMode,
) -> eyre::Result<PathBuf> {
    let out_dir = output_dir.join(project);
    std::fs::create_dir_all(&out_dir)?;
    let elf_path = out_dir.join("app");

    if matches!(mode, BuildMode::Auto) && elf_path.exists() {
        info!("ELF already exists at {}, skipping build", elf_path.display());
        return Ok(elf_path);
    }

    let mut build_args = sp1_build::BuildArgs::default();
    build_args.elf_name = Some("app".to_string());
    build_args.output_directory = Some(out_dir.to_string_lossy().to_string());

    build_program_with_args(program_dir.to_str().unwrap(), build_args);

    Ok(elf_path)
}
