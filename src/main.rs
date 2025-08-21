mod environment;
mod nexus_orchestrator;
mod orchestrator;
mod prover;
pub mod system;
mod task;
mod verifier;

use crate::environment::Environment;
use crate::nexus_orchestrator::TaskType;
use crate::orchestrator::error::OrchestratorError;
use crate::orchestrator::{Orchestrator, OrchestratorClient};
use crate::prover::ProverResult;
use ed25519_dalek::SigningKey;
use hex::encode;
use nexus_sdk::stwo::seq::Proof;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::io::{self, Read};
use tokio::runtime::Runtime;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Deserialize, Clone)]
struct TaskRequest {
    #[serde(rename = "taskId")]
    task_id: String,
    #[serde(rename = "programId")]
    program_id: String,
    #[serde(rename = "publicInputs")]
    public_inputs_list: String,
    #[serde(rename = "taskType")]
    task_type: i32,
    #[serde(rename = "signKey")]
    sign_key: String,
}

#[derive(Debug, Serialize)]
struct ComputeResult {
    task_id: String,
    combined_hash: Option<String>,
    proof: Option<String>, // Base64编码的字节序列
    proof_hashes: Option<Vec<String>>,
    error: Option<String>,
}

/// Proof submission data grouped by business concern
#[derive(Debug, Clone)]
pub struct ProofSubmission {
    pub task_id: String,
    pub proof_hash: String,
    pub proof_bytes: Vec<u8>,
    pub task_type: crate::nexus_orchestrator::TaskType,
    pub individual_proof_hashes: Vec<String>,
    pub proofs_bytes: Vec<Vec<u8>>, // new: full proofs array
}

impl ProofSubmission {
    pub fn new(
        task_id: String,
        proof_hash: String,
        proof_bytes: Vec<u8>,
        task_type: crate::nexus_orchestrator::TaskType,
    ) -> Self {
        Self {
            task_id,
            proof_hash,
            proof_bytes,
            task_type,
            individual_proof_hashes: Vec::new(),
            proofs_bytes: Vec::new(),
        }
    }

    pub fn with_individual_hashes(mut self, hashes: Vec<String>) -> Self {
        self.individual_proof_hashes = hashes;
        self
    }

    pub fn with_proofs(mut self, proofs: Vec<Vec<u8>>) -> Self {
        self.proofs_bytes = proofs;
        self
    }
}
fn main() {
    // 获取命令行参数
    let args: Vec<String> = std::env::args().collect();

    // 确保有足够的参数
    if args.len() < 2 {
        println!("Usage: {} <input_json>", args[0]);
        return;
    }

    // 第一个命令行参数是JSON数据
    let input = &args[1];

    // 解析JSON数据
    let payload: TaskRequest = match serde_json::from_str(&input) {
        Ok(p) => p,
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({
                    "error": format!("JSON解析失败: {}", e)
                })
            );
            return;
        }
    };

    // 创建Tokio运行时环境
    let rt = Runtime::new().expect("无法创建运行时");
    let result = rt.block_on(async {
        // 准备任务数据
        let task = prover::Task::from(payload.clone());
        // 尝试证明任务
        let proof;
        if task.public_inputs_list.len() > 1 {
            proof = prover::prove_task2(task.clone(), None).unwrap();
        } else {
            proof = prover::prove_task(task.clone()).unwrap();
        }

        // // Convert sign key
        // let bytes = hex::decode(payload.sign_key).unwrap();
        // let mut array = [0u8; 64];

        // array.copy_from_slice(&bytes);

        // // Submit to orchestrator
        // let signing_key = SigningKey::from_keypair_bytes(&array).unwrap();
        // let proof_bytes = postcard::to_allocvec(&proof.proof).unwrap();
        // println!("3---{:x}\n\n\n", Keccak256::digest(&proof_bytes));

        // Convert sign key
        let bytes = hex::decode(payload.sign_key).unwrap();

        let mut array = [0u8; 64];

        array.copy_from_slice(&bytes);

        // Submit to orchestrator
        let signing_key = SigningKey::from_keypair_bytes(&array).unwrap();
        let proofs_bytes: Vec<Vec<u8>> = proof
            .proof
            .iter()
            .map(postcard::to_allocvec)
            .collect::<Result<_, _>>()
            .unwrap();
        let legacy_proof_bytes = proofs_bytes.first().cloned().unwrap_or_default();
        // Submit through network client with retry logic
        let mut submission = ProofSubmission::new(
            task.task_id.clone(),
            proof.combined_hash.clone(),
            legacy_proof_bytes,
            task.task_type,
        );

        // Populate individual hashes for ALL_PROOF_HASHES and optionally for ProofHash
        if task.task_type == crate::nexus_orchestrator::TaskType::AllProofHashes {
            submission = submission.with_individual_hashes(proof.individual_proof_hashes.clone());
        }

        // Populate proofs for PROOF_REQUIRED; leave empty otherwise
        if task.task_type == crate::nexus_orchestrator::TaskType::ProofRequired {
            submission = submission.with_proofs(proofs_bytes);
        }

        let client = OrchestratorClient::new(Environment::Beta);
        let resbytes = client
            .submit_proof(
                &submission.task_id,
                &submission.proof_hash,
                submission.proof_bytes.clone(),
                submission.proofs_bytes.clone(),
                signing_key.clone(),
                1,
                task.task_type,
                &submission.individual_proof_hashes,
            )
            .await;
        resbytes
    });
    let hex_string = encode(result);
    println!("{}", hex_string); // 输出: deadbeef
    // println!("{}", result);
    // // 处理最终结果并输出
    // let output = match result {
    //     Ok(success) => serde_json::to_string_pretty(&success).expect("序列化失败"),
    //     Err(error_msg) => serde_json::to_string_pretty(&ComputeResult {
    //         task_id: payload.task_id.clone(),
    //         combined_hash: None,
    //         proof: None,
    //         proof_hashes: None,
    //         signing_key_bytes: None,
    //         error: Some(error_msg),
    //     })
    //     .expect("序列化失败"),
    // };
}

fn generate_proof_hash(proof: &Proof) -> String {
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    format!("{:x}", Keccak256::digest(&proof_bytes))
}
