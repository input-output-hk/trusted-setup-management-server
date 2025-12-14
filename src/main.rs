use actix_files::Files;
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use futures_util::StreamExt;
use parking_lot::RwLock;
use rand::{rng, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, ReadDir};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::process::{Command, Stdio};
use std::sync::LazyLock;

static CURR_STEP: RwLock<SrsSteps> = RwLock::new(SrsSteps::Idle);
static ERROR: RwLock<String> = RwLock::new(String::new());
static SRS_RESULT: LazyLock<RwLock<SRSResult>> =
    LazyLock::new(|| RwLock::new(SRSResult::default()));

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SRSResult {
    sha256_original: String,
    attestation: String,
    sha256_srs: String,
    sha256_proof: String,
    sha256_srs_utils: String,
    sha256_srs_srv: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
enum SrsSteps {
    Idle = 0,
    DownloadPowerOfTau,
    GenerateSRS,
    Done,
    Error,
}

impl std::fmt::Display for SrsSteps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SrsSteps::Idle => write!(f, "Idle"),
            SrsSteps::DownloadPowerOfTau => write!(f, "Downloading Power of Tau"),
            SrsSteps::GenerateSRS => write!(f, "Generating SRS"),
            SrsSteps::Done => write!(f, "Done. The process is complete and CANNOT be restarted."),
            SrsSteps::Error => write!(f, "Error during the process. The process can be restarted."),
        }
    }
}

pub fn hexdump(bytes: &[u8], pretty_print: bool) -> String {
    let mut retval: String = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if pretty_print {
            if (i % 16) == 0 {
                retval.push('\n');
            }
            retval.push_str(&format!("{:02x} ", byte));
            retval.push('\n');
        } else {
            retval.push_str(&format!("{byte:02x}"));
        }
    }
    retval
}

pub fn open_dir(path: &Path) -> ReadDir {
    fs::read_dir(path).unwrap_or_else(|err| panic!("Failed to open dir '{:?}': {}", path, err))
}

pub fn derive_new_path(old_path: &Path) -> (PathBuf, PathBuf) {
    let proofs_path = Path::new("proofs/");

    let n = open_dir(proofs_path).filter_map(|entry| entry.ok()).count() + 1;

    let new_srs_path = old_path.parent().unwrap().join(format!("srs{n}"));
    let new_proof_path = proofs_path.join(format!("proof{n}"));

    (new_srs_path, new_proof_path)
}

fn generate_random_entropy(len: usize) -> String {
    let mut rng = rng();
    const CHARSET: &[u8] = b"abcdefghijkilmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let one_char = || CHARSET[rng.random_range(0..CHARSET.len())] as char;
    std::iter::repeat_with(one_char).take(len).collect()
}

pub fn compute_sha256(path: &PathBuf) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let file = std::fs::File::open(path).expect("Could not open file");
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = Vec::new();

    reader
        .read_to_end(&mut buffer)
        .expect("Could not read file");
    hasher.update(&buffer);
    hasher.finalize().into()
}

async fn run_srs_utils(
    sha_srs: String,
    srs_path: &PathBuf,
    proof_path: &PathBuf,
) -> Result<SRSResult, Box<dyn std::error::Error + Send + Sync>> {
    let random_string = generate_random_entropy(32);

    let mut child = Command::new("./srs_utils")
        .arg("./powers_of_tau")
        .arg("update")
        .arg(random_string)
        // RDRAND in TEE.
        .arg("true")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let result = child.wait()?;
    if !result.success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SRS Utils command failed with status: {}", result),
        )));
    }

    println!("Getting hashes of the SRS and proof files...");
    let srs_hash = compute_sha256(srs_path);
    let proof_hash = compute_sha256(proof_path);
    let mut both_hashes = vec![];
    both_hashes.extend_from_slice(&srs_hash);
    both_hashes.extend_from_slice(&proof_hash);
    println!("Hashes computed successfully!");
    println!("SRS hash: {:x?}", srs_hash);
    println!("Proof hash: {:x?}", proof_hash);
    println!("Both hashes: {:x?}", both_hashes);
    println!("Writing hashes to file...");

    let mut file_hash = BufWriter::new(
        File::create("./proof_hash.bin").expect("Could not create proof_hash.bin file"),
    );
    file_hash
        .write_all(&both_hashes)
        .expect("Could not write to proof_hash.bin file");
    file_hash
        .flush()
        .expect("Could not flush proof_hash.bin file");

    println!("Hashes of the SRS and proof files have been successfully written to proof_hash.bin!");

    println!("Now generating AMD-SEV-SNP attestation...");
    let result = StdCommand::new("sudo")
        .arg("./AttestationClient")
        .arg("-o")
        .arg("attestation.txt")
        .arg("-h")
        .arg("proof_hash.bin")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| eprintln!("Failed to run AttestationClient: {}", e));

    match result {
        Ok(status) if status.success() => {
            println!("AMD-SEV-SNP attestation has been successfully generated and saved to attestation.txt!");
        }
        Ok(status) => {
            eprintln!("AttestationClient failed with exit code: {}", status);
        }
        Err(err) => {
            eprintln!("AttestationClient failed with error: {:?}", err);
        }
    }
    let attestation_file = std::fs::read_to_string("attestation.txt")?;
    let srs_hash = hexdump(&both_hashes[..32], false);
    let proof_hash = hexdump(&both_hashes[32..], false);
    let apps_hashes = std::fs::read("app_hashes.bin")?;
    let sha_srs_utils = hexdump(&apps_hashes[..32], false);
    let sha_srs_srv = hexdump(&apps_hashes[32..], false);
    let srs_res = SRSResult {
        sha256_original: sha_srs,
        attestation: attestation_file,
        sha256_srs: srs_hash,
        sha256_proof: proof_hash,
        sha256_srs_utils: sha_srs_utils,
        sha256_srs_srv: sha_srs_srv,
    };
    Ok(srs_res)
}

async fn download_power_of_tau() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let resp = client
        .get("https://srs.midnight.network/current_srs/powers_of_tau")
        .send()
        .await?
        .error_for_status()?;

    let mut file = std::fs::File::create("powers_of_tau")?;
    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        hasher.update(&chunk);
        file.write_all(&chunk)?;
    }

    file.flush()?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn dump_srs_result_to_file(
    srs_res: SRSResult,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut result = SRS_RESULT.write();
    *result = srs_res.clone();
    drop(result);
    let serialized_srs = bincode::serialize(&srs_res)?;
    std::fs::write("srs_result.bin", serialized_srs)?;
    Ok(())
}

fn move_artifacts(
    srs_path: PathBuf,
    proof_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let srs_name = srs_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid SRS path")?;
    let proof_name = proof_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid proof path")?;

    std::fs::rename("./powers_of_tau", "./artifacts/powers_of_tau")?;
    std::fs::rename(
        format!("./{}", srs_name),
        format!("./artifacts/{}", srs_name),
    )?;
    std::fs::copy(
        format!("./proofs/{}", proof_name),
        format!("./artifacts/{}", proof_name),
    )?;
    Ok(())
}

#[get("/")]
async fn root() -> impl Responder {
    HttpResponse::Ok().body("Midnight trusted-setup is running!")
}

#[get("/health")]
async fn health() -> impl Responder {
    let step = CURR_STEP.read();
    if *step == SrsSteps::Error {
        let error_message = ERROR.read();
        return HttpResponse::InternalServerError().body(format!(
            "Current step: {}. Error message: {}",
            step.to_string(),
            *error_message
        ));
    }
    let health_status = format!("Current step: {}", step.to_string());
    HttpResponse::Ok().body(health_status)
}

#[get("/calculate")]
async fn calculate() -> impl Responder {
    let mut step = CURR_STEP.write();
    if *step == SrsSteps::Idle || *step == SrsSteps::Error {
        *step = SrsSteps::DownloadPowerOfTau;
        drop(step); // Release the lock before spawning
        tokio::spawn(async move {
            println!("Starting download of Power of Tau...");
            let sha256;
            match download_power_of_tau().await {
                Ok(sha) => {
                    let mut step = CURR_STEP.write();
                    *step = SrsSteps::GenerateSRS;
                    sha256 = sha;
                }
                Err(e) => {
                    let mut error = ERROR.write();
                    let mut step = CURR_STEP.write();
                    *error = format!("Error downloading power of tau: {}", e);
                    *step = SrsSteps::Error;
                    return;
                }
            }
            println!("Power of Tau downloaded successfully.");
            println!("SHA256 of the downloaded file: {}", sha256);
            let (srs_path, proof_path) = derive_new_path(Path::new("./powers_of_tau"));
            println!("Derived SRS path: {:?}", srs_path);
            println!("Derived Proof path: {:?}", proof_path);
            match run_srs_utils(sha256, &srs_path, &proof_path).await {
                Ok(srs) => {
                    println!("SRS generation completed successfully.");
                    dump_srs_result_to_file(srs).unwrap_or_else(|e| {
                        let mut error = ERROR.write();
                        let mut step = CURR_STEP.write();
                        *error = format!("Error dumping SRS result to file: {}", e);
                        *step = SrsSteps::Error;
                    });
                }
                Err(e) => {
                    let mut error = ERROR.write();
                    let mut step = CURR_STEP.write();
                    *error = format!("Error running srs_utils: {}", e);
                    *step = SrsSteps::Error;
                    return;
                }
            }
            println!("SRS Utils command executed successfully.");
            println!("Attestation command executed successfully.");
            println!("All steps completed successfully.");
            let _ = move_artifacts(srs_path, proof_path);
            {
                let mut step = CURR_STEP.write();
                *step = SrsSteps::Done;
            }
        });
        return HttpResponse::Ok().body("Calculation started.");
    } else if *step < SrsSteps::Done {
        return HttpResponse::BadRequest().body(format!(
            "A process is already ongoing. Current step: {}",
            step.to_string()
        ));
    } else {
        return HttpResponse::Ok().json(SRS_RESULT.read().clone());
    }
}

async fn run_attestation_test() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut child = Command::new("./AttestationClient")
        .arg("-o")
        .arg("attestation_test.txt")
        .arg("-h")
        .arg("test_hashes.bin")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let result = child.wait()?;
    if !result.success() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Attestation command failed with status: {}", result),
        )));
    }
    let attestation_file = std::fs::read_to_string("attestation_test.txt")?;
    Ok(attestation_file)
}

#[get("/test_attestation")]
async fn test_attestation() -> impl Responder {
    match run_attestation_test().await {
        Ok(attestation) => {
            return HttpResponse::Ok().body(attestation);
        }
        Err(e) => {
            let mut error = ERROR.write();
            *error = format!("Error during attestation test: {}", e);
            return HttpResponse::InternalServerError()
                .body(format!("Attestation test failed: {}", e));
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if let Err(e) = init_srv() {
        eprintln!("Error loading SRS results {}. Setting state to Idle, allowing new calculations to be made.", e);
    }
    HttpServer::new(|| {
        App::new()
            .service(root)
            .service(health)
            .service(calculate)
            .service(test_attestation)
            .service(Files::new("/artifacts", "./artifacts").show_files_listing())
    })
    .workers(8)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn init_srv() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Err(e) = std::fs::create_dir_all("./artifacts") {
        eprintln!("Failed to create artifacts directory: {}", e);
    }
    if let Ok(_metadata) = std::fs::metadata("srs_result.bin") {
        let serialized_srs = std::fs::read("srs_result.bin")?;
        let srs_res: SRSResult = bincode::deserialize(&serialized_srs)?;
        *SRS_RESULT.write() = srs_res;
        *CURR_STEP.write() = SrsSteps::Done;
        println!(
            "Restored SRS results. Setting current step to Done, preventing further calculations."
        );
    } else {
        println!("srs_result.bin not found, starting with an empty state.");
    }
    Ok(())
}
