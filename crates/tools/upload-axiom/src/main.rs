use axiom_sdk::AxiomConfig;
use axiom_sdk::build::{BuildSdk, UploadExeArgs};
use axiom_sdk::config::ConfigSdk;
use axiom_sdk::projects::ProjectSdk;
use clap::ArgGroup;
use clap::{Parser, ValueEnum};
use console::{Emoji, style};
use dotenvy::dotenv;
use eyre::Context;
use inquire::{Confirm, Text};
use jiff::civil::{DateTime, DateTimeDifference};
use jiff::tz::TimeZone;
use jiff::{Timestamp, Unit, Zoned};
use openvm_sdk::commit::CommitBytes;
use scroll_zkvm_types::axiom::{AxiomProgram, get_config_id};
use scroll_zkvm_types::utils::serialize_vk;
use std::collections::HashMap;
use std::fs::File;
use std::io::{IsTerminal, stderr, stdout};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

#[derive(Parser)]
#[command(name = "upload-axiom")]
#[command(about = "Upload guest program (chunk, batch, bundle) to Axiom")]
#[command(
    group(
        ArgGroup::new("project_selection")
            .args(&["project_id", "create_project"])
            .required(true)
            .multiple(false)
    )
)]
#[command(
    group(
        ArgGroup::new("program_ids")
            .args(&["no_write_ids", "upload_s3"])
            .required(false)
            .multiple(false)
    )
)]
struct Cli {
    /// Guest program version
    ///
    /// "dev" or specific version like "0.5.0"
    #[arg(short = 'v', long, default_value = "dev", env = "GUEST_VERSION")]
    guest_version: String,
    /// Projects to upload
    ///
    /// Comma separated list of "chunk", "batch", "bundle"
    #[arg(
        short = 'p',
        long,
        env = "PROJECTS_TO_UPLOAD",
        value_delimiter = ',',
        default_value = "chunk,batch,bundle"
    )]
    uploads: Vec<String>,
    /// Don't write program ids json
    #[arg(long)]
    no_write_ids: bool,
    /// Uploads program ids json to s3 if available
    #[arg(long)]
    upload_s3: bool,

    /// The directory containing the manifest of the crate to run this command in.
    #[arg(long, env = "CARGO_MANIFEST_DIR")]
    manifest_dir: PathBuf,

    /// Axiom API Key
    #[arg(
        long,
        env = "AXIOM_API_KEY",
        help_heading = "Axiom Configuration",
        hide_env_values = true
    )]
    api_key: String,
    /// Axiom Project ID
    #[arg(long, env = "AXIOM_PROJECT_ID", help_heading = "Axiom Configuration")]
    project_id: Option<String>,
    /// Create new Axiom Project with this name
    #[arg(long, help_heading = "Axiom Configuration")]
    create_project: Option<String>,
    #[arg(
        long,
        default_value = "https://api.axiom.xyz/v1",
        help_heading = "Axiom Configuration"
    )]
    api_url: String,

    /// Answer yes to all prompts
    #[arg(short = 'y', long = "yes", help_heading = "Miscellaneous")]
    yes: bool,
    /// Dry run mode
    #[arg(long, help_heading = "Miscellaneous")]
    dry_run: bool,
    /// Coloring
    #[arg(long, default_value = "auto", help_heading = "Miscellaneous")]
    color: ColorChoice,
}

#[derive(Copy, Clone, ValueEnum, Debug)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

const LOG_PREFIX: &str = "[upload-axiom]";
const OK: Emoji = Emoji("✅", "✓ ");
const WARN: Emoji = Emoji("⚠️", "! ");

fn main() -> eyre::Result<()> {
    // Load .env file if present
    dotenv().ok();
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.color {
        ColorChoice::Always => {
            console::set_colors_enabled(true);
            console::set_colors_enabled_stderr(true);
        }
        ColorChoice::Never => {
            console::set_colors_enabled(false);
            console::set_colors_enabled_stderr(false);
        }
        _ => {}
    }

    // Set current directory to the crate's root
    env::set_current_dir(&cli.manifest_dir)?;

    let interactive = stdout().is_terminal() && stderr().is_terminal();
    let assume_yes = cli.yes || !interactive;

    let metadata = cargo_metadata::MetadataCommand::new().no_deps().exec()?;
    let workspace_dir = metadata.workspace_root.into_std_path_buf();

    let guest_version = if interactive {
        Text::new("Guest version:")
            .with_initial_value(&cli.guest_version)
            .prompt()?
    } else {
        cli.guest_version
    };

    let axiom_config = AxiomConfig {
        api_url: cli.api_url,
        api_key: Some(cli.api_key),
        ..Default::default()
    };

    let sdk = axiom_sdk::AxiomSdk::new(axiom_config.clone());

    let project_id = if let Some(project_name) = cli.create_project {
        let project_id = sdk.create_project(&project_name)?.id;
        println!(
            "{LOG_PREFIX} {OK} Created new Axiom project '{project_name}' with ID: {project_id}"
        );
        project_id
    } else {
        cli.project_id.unwrap()
    };

    let guest_dir = workspace_dir.join("releases").join(&guest_version);

    let vks: HashMap<String, String> = serde_json::from_reader(
        File::open(guest_dir.join("verifier").join("openVmVk.json"))
            .context("Failed to open openVmVk.json")?,
    )
    .context("Failed to parse openVmVk.json")?;

    for project in cli.uploads.iter() {
        if !vks.contains_key(&format!("{project}_vk")) {
            eyre::bail!("Project '{project}' not found in openVmVk.json");
        }
    }

    let mut program_ids = HashMap::new();

    for project in cli.uploads {
        let Some(vk) = vks.get(&format!("{project}_vk")) else {
            eyre::bail!("Project '{project}' not found in openVmVk.json");
        };

        let styled_project = style(&project).bold().green();
        let dir = guest_dir.join(&project);

        let config_id = get_config_id(&project);
        let sdk = axiom_sdk::AxiomSdk::new(AxiomConfig {
            config_id: Some(config_id.to_string()),
            ..axiom_config.clone()
        });

        // verify config_id is correct
        let commitment = serialize_vk::deserialize(&hex::decode(vk)?);
        let vm_commitment = CommitBytes::from_u32_digest(&commitment.vm);
        let config_vm_commitment = sdk.get_vm_config_metadata(Some(config_id))?.app_vm_commit;
        let config_vm_commitment = hex::decode(config_vm_commitment)?;
        if vm_commitment.as_slice() == config_vm_commitment.as_slice() {
            println!("{LOG_PREFIX} {OK} config_id VM commitment matches.");
        } else {
            let abort = assume_yes
                || !Confirm::new(&format!(
                    "{WARN} VM commitment mismatch for project {styled_project}. Continue anyway?"
                ))
                .with_default(false)
                .prompt()?;
            if abort {
                println!(
                    "{LOG_PREFIX} {WARN} invalid config_id for project {styled_project}, skipping upload..."
                );
                continue;
            }
        }

        let app_elf = dir.join("app.elf");
        let app_vmexe = dir.join("app.vmexe");

        // Print metadata for double check
        println!("{LOG_PREFIX} Preparing to upload project {styled_project}:");
        print_metadata(&app_elf)?;
        print_metadata(&app_vmexe)?;

        let proceed = assume_yes
            || Confirm::new(&format!("Proceed to upload {styled_project} to Axiom?"))
                .with_default(false)
                .prompt()?;
        if !proceed {
            println!("Skipping upload of {styled_project}");
            continue;
        }

        println!("{LOG_PREFIX} Uploading project {styled_project}...");

        let program_id = sdk.upload_exe_raw(
            fs::read(app_elf)?,
            fs::read(app_vmexe)?,
            UploadExeArgs {
                config_id: Some(config_id.to_string()),
                project_id: Some(project_id.clone()),
                project_name: None,
                bin_name: Some(project.clone()),
                program_name: Some(project.clone()),
                default_num_gpus: None,
            },
        )?;
        println!(
            "{LOG_PREFIX} {OK} Uploaded project {styled_project} with Program ID: {program_id}"
        );

        program_ids.insert(vk, AxiomProgram::new(config_id, program_id));
    }

    if !cli.no_write_ids {
        let output_path = guest_dir.join("axiom_program_ids.json");
        fs::write(&output_path, serde_json::to_string_pretty(&program_ids)?)?;
        println!(
            "{LOG_PREFIX} {OK} Wrote Axiom program IDs to {}",
            output_path.display()
        );

        // "s3://circuit-release/scroll-zkvm/releases/$GUEST_VERSION/axiom_program_ids.json"
        // aws --profile default s3 cp
        if cli.upload_s3 {
            let s3_path = format!(
                "s3://circuit-release/scroll-zkvm/releases/{guest_version}/axiom_program_ids.json"
            );
            let status = Command::new("aws")
                .arg("--profile")
                .arg("default")
                .arg("s3")
                .arg("cp")
                .arg(output_path)
                .arg(&s3_path)
                .status()?;
            if status.success() {
                println!("{LOG_PREFIX} {OK} Uploaded axiom_program_ids.json to {s3_path}");
            } else {
                println!(
                    "{LOG_PREFIX} {WARN} Failed to upload axiom_program_ids.json to {s3_path}"
                );
            }
        }
    }

    Ok(())
}

fn print_metadata<P: AsRef<Path>>(path: P) -> eyre::Result<()> {
    let now: DateTime = Zoned::now().into();

    let name = path.as_ref().file_name().unwrap().to_string_lossy();
    let metadata = fs::metadata(&path)?;

    println!("- {}:", name);
    println!("  - size: {} bytes", metadata.len());

    let created: DateTime = Timestamp::try_from(metadata.created()?)?
        .to_zoned(TimeZone::system())
        .into();
    let passed = created.until(DateTimeDifference::new(now).smallest(Unit::Second))?;
    println!("  - created: {passed:#} ago ({created:#})");
    Ok(())
}
