use super::TaskProver;
use axiom_sdk::build::BuildSdk;
use axiom_sdk::config::ConfigSdk;
use axiom_sdk::input::Input;
use axiom_sdk::prove::{ProveArgs, ProveSdk};
use axiom_sdk::{AxiomConfig, AxiomSdk, ProgressCallback, ProofType, SaveOption};
use chrono::DateTime;
use openvm_sdk::commit::CommitBytes;
use openvm_sdk::types::{EvmProof, VersionedVmStarkProof};
use scroll_zkvm_types::ProvingTask as UniversalProvingTask;
use scroll_zkvm_types::proof::ProofEnum;
use scroll_zkvm_types::types_agg::ProgramCommitment;
use scroll_zkvm_types::utils::serialize_vk;
use std::env;

pub struct AxiomProver {
    name: String,
    sdk: AxiomSdk,
    program_id: String,
}

struct TracingProgressCallback;

impl AxiomProver {
    /// Create a new client
    pub fn from_env(name: String, config_id: String, program_id: String) -> Self {
        let api_key = env::var("AXIOM_API_KEY").expect("AXIOM_API_KEY env var is required");
        let config = AxiomConfig {
            api_key: Some(api_key),
            config_id: Some(config_id),
            ..Default::default()
        };
        let sdk = AxiomSdk::new(config).with_callback(TracingProgressCallback);
        Self {
            name,
            sdk,
            program_id,
        }
    }

    pub fn get_app_commitment(&mut self) -> eyre::Result<ProgramCommitment> {
        let vm_commitment = self.sdk.get_vm_config_metadata(None)?.app_vm_commit;
        let vm_commitment: [u8; _] = hex::decode(vm_commitment)?.try_into().unwrap();
        let app_exe_commit: [u8; _] = self
            .sdk
            .get_app_exe_commit(&self.program_id)?
            .try_into()
            .unwrap();

        let exe = CommitBytes::new(app_exe_commit).to_u32_digest();
        let vm = CommitBytes::new(vm_commitment).to_u32_digest();

        Ok(ProgramCommitment { exe, vm })
    }
}

impl TaskProver for AxiomProver {
    fn name(&self) -> &str {
        &self.name
    }

    fn prove_task(&mut self, t: &UniversalProvingTask, gen_snark: bool) -> eyre::Result<ProofEnum> {
        let input = serde_json::to_value(t.build_openvm_input())?;

        let proof_type = if gen_snark {
            ProofType::Evm
        } else {
            ProofType::Stark
        };

        let job_id = self.sdk.generate_new_proof(ProveArgs {
            program_id: Some(self.program_id.clone()),
            input: Some(Input::Value(input)),
            proof_type: Some(proof_type),
            num_gpus: None,
            priority: None,
        })?;

        let status = self.sdk.wait_for_proof_completion(&job_id, false)?;
        if status.state.as_str() != "Succeeded" {
            return Err(eyre::eyre!(
                "Proof generation failed with status: {}",
                status.state
            ));
        }
        tracing::info!(name: "wait_for_proof_completion", "{status:#?}");

        let cycles = status.num_instructions.unwrap();
        let launched_at = DateTime::parse_from_rfc3339(status.launched_at.as_deref().unwrap())?;
        let terminated_at = DateTime::parse_from_rfc3339(status.terminated_at.as_deref().unwrap())?;
        let duration = terminated_at
            .signed_duration_since(launched_at)
            .as_seconds_f64();
        let mhz = cycles as f64 / duration / 1e6f64;
        tracing::info!("Proof generated in {duration:.2} seconds: {mhz:.2} MHz");

        let proof_bytes =
            self.sdk
                .get_generated_proof(&status.id, &proof_type, SaveOption::DoNotSave)?;

        match proof_type {
            ProofType::Stark => {
                let proof: VersionedVmStarkProof = serde_json::from_slice(&proof_bytes)?;
                Ok(ProofEnum::Stark(
                    proof.try_into().expect("Failed to convert to StarkProof"),
                ))
            }
            ProofType::Evm =>  {
                let proof: EvmProof = serde_json::from_slice(&proof_bytes)?;
                Ok(ProofEnum::Evm(proof.into()))
            }
        }
    }

    fn get_vk(&mut self) -> eyre::Result<Vec<u8>> {
        Ok(serialize_vk::serialize(&self.get_app_commitment()?))
    }
}

impl ProgressCallback for TracingProgressCallback {
    fn on_header(&self, text: &str) {
        tracing::info!("{text}");
    }

    fn on_success(&self, text: &str) {
        tracing::info!("{text}");
    }

    fn on_info(&self, text: &str) {
        tracing::info!("{text}");
    }

    fn on_warning(&self, text: &str) {
        tracing::warn!("{text}");
    }

    fn on_error(&self, text: &str) {
        tracing::error!("{text}");
    }

    fn on_section(&self, title: &str) {
        tracing::info!("{title}:");
    }

    fn on_field(&self, key: &str, value: &str) {
        tracing::info!("  {key}: {value}");
    }

    fn on_status(&self, text: &str) {
        tracing::info!("status={text}");
    }

    fn on_progress_start(&self, _message: &str, _total: Option<u64>) {}

    fn on_progress_update(&self, _current: u64) {}

    fn on_progress_update_message(&self, _message: &str) {}

    fn on_progress_finish(&self, _message: &str) {}

    fn on_clear_line(&self) {}

    fn on_clear_line_and_reset(&self) {}
}
