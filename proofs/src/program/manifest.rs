//! Proof composition is required to stitch different [`crate::program::RomCircuit`] together to
//! form an NIVC [`crate::program::data::InstanceParams`].
//!
//! [`Manifest`] generated by client contains [`ManifestRequest`] and [`ManifestResponse`] which is
//! used to create HTTP and JSON circuits. To create the circuits, ROM is prepared containing
//! circuits and private input to each circuit.
//!
//! Circuits:
//! - Plaintext Authentication: verifies encryption of plaintext with TLS key matches ciphertext
//! - HTTP Verification: verifies HTTP headers and body
//! - JSON Extraction: verifies JSON keys in the response body
//!
//! # Example ROM for Request
//! ```json
//! {
//!    "PLAINTEXT_AUTHENTICATION": 0,
//!    "HTTP_VERIFICATION": 1
//! }
//! ```
//!
//! # Example ROM for Response
//! ```json
//! {
//!    "PLAINTEXT_AUTHENTICATION": 0,
//!    "HTTP_VERIFICATION": 1,
//!    "JSON_EXTRACTION": 2
//! }

use std::collections::HashMap;

use derive_more::From;
use ff::Field;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tls_client2::CipherSuiteKey;
use tracing::debug;
use web_proof_circuits_witness_generator::{
  data_hasher, field_element_to_base10_string,
  http::{
    compute_http_witness, headers_to_bytes, parser::parse as http_parse, HttpMaskType,
    RawHttpMachine,
  },
  json::{json_value_digest, parser::parse, JsonKey, RawJsonMachine},
  polynomial_digest, poseidon, ByteOrPad,
};
use web_prover_core::{http::MAX_HTTP_HEADERS, manifest::Manifest};

use crate::{
  circuits::MAX_STACK_HEIGHT,
  program::{
    data::{CircuitData, FoldInput},
    F, G1,
  },
  ProofError,
};

/// HTTP data signal name
pub const DATA_SIGNAL_NAME: &str = "data";
/// Public IO vars
pub const PUBLIC_IO_VARS: usize = 11;

/// A type of `Manifest` with special methods for Origo mode.
#[derive(Debug, Clone, Serialize, Deserialize, From)]
pub struct OrigoManifest(pub(crate) Manifest);

impl TryFrom<&[u8]> for OrigoManifest {
  type Error = serde_json::Error;

  fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
    serde_json::from_slice(bytes).map(OrigoManifest)
  }
}

impl TryFrom<&OrigoManifest> for Vec<u8> {
  type Error = serde_json::Error;

  fn try_from(manifest: &OrigoManifest) -> Result<Self, Self::Error> {
    serde_json::to_vec(&manifest.0)
  }
}

impl From<OrigoManifest> for Manifest {
  fn from(value: OrigoManifest) -> Self { value.0 }
}

impl OrigoManifest {
  /// Initial inputs
  pub fn initial_inputs<const MAX_STACK_HEIGHT: usize, const CIRCUIT_SIZE: usize>(
    &self,
    // TODO (Sambhav): can remove copying
    request_ciphertext: &[Vec<u8>],
    response_ciphertext: &[Vec<u8>],
  ) -> Result<InitialNIVCInputs, ProofError> {
    let ciphertext_digest =
      compute_ciphertext_digest::<CIRCUIT_SIZE>(request_ciphertext, response_ciphertext);

    // TODO: This assumes the start line format here as well.
    // digest the start line for request/response using the ciphertext_digest as a random input
    let request_start_line_bytes =
      format!("{} {} {}", &self.0.request.method, &self.0.request.url, &self.0.request.version);
    let request_start_line_digest =
      polynomial_digest(request_start_line_bytes.as_bytes(), ciphertext_digest, 0);
    debug!(
      "WITNESS (request): start_line_digest={:?}, hex={:?}",
      request_start_line_digest,
      hex::encode(request_start_line_digest.to_bytes())
    );

    let response_start_line_bytes = format!(
      "{} {} {}",
      &self.0.response.version, &self.0.response.status, &self.0.response.message
    );
    let response_start_line_digest =
      polynomial_digest(response_start_line_bytes.as_bytes(), ciphertext_digest, 0);

    // Digest all the headers
    let request_header_bytes = headers_to_bytes(&self.0.request.headers);
    let request_headers_digest =
      request_header_bytes.map(|bytes| polynomial_digest(&bytes, ciphertext_digest, 0));
    // debug!(
    //   "WITNESS (request): headers_digest={:?}, hex={:?}",
    //   request_headers_digest,
    //   request_headers_digest.clone().into_iter().map(|f| hex::encode(f.to_bytes()))
    // );

    let response_header_bytes = headers_to_bytes(&self.0.response.headers);
    let response_headers_digest =
      response_header_bytes.map(|bytes| polynomial_digest(&bytes, ciphertext_digest, 0));
    // debug!(
    //   "WITNESS (response): headers_digest={:?}, hex={:?}",
    //   response_headers_digest,
    //   response_headers_digest.clone().into_iter().map(|f| hex::encode(f.to_bytes()))
    // );

    // Digest the JSON sequence
    let raw_response_json_machine =
      RawJsonMachine::<MAX_STACK_HEIGHT>::from_chosen_sequence_and_input(
        ciphertext_digest,
        &self.0.response.body.json_path(),
      )?;
    let json_sequence_digest_hash =
      poseidon::<1>(&[raw_response_json_machine.compress_tree_hash()]);

    // push request/response start line digest and headers digest into one all_digest vec
    let mut all_digest = vec![request_start_line_digest, response_start_line_digest];
    all_digest.extend(request_headers_digest);
    all_digest.extend(response_headers_digest);

    let header_verification_lock = all_digest.iter().map(|d| poseidon::<1>(&[*d])).sum::<F<G1>>();
    let num_matches = 1 + self.0.request.headers.len() + 1 + self.0.response.headers.len();

    let initial_http_machine_digest =
      polynomial_digest(&[1, 0, 0, 0, 0, 0, 0, 1], ciphertext_digest, 0);

    Ok(InitialNIVCInputs {
      ciphertext_digest,
      initial_nivc_input: [
        ciphertext_digest,
        F::<G1>::ONE,
        F::<G1>::ONE,
        initial_http_machine_digest,
        header_verification_lock,
        F::<G1>::from(num_matches as u64),
        F::<G1>::ZERO,
        F::<G1>::ONE,
        F::<G1>::ZERO,
        json_sequence_digest_hash,
        F::<G1>::ZERO,
      ],
      headers_digest: all_digest,
    })
  }

  /// Builds inputs
  pub fn build_inputs<const CIRCUIT_SIZE: usize>(
    &self,
    request_inputs: &EncryptionInput,
    response_inputs: &EncryptionInput,
  ) -> Result<NivcCircuitInputs, ProofError> {
    assert_eq!(request_inputs.plaintext.len(), request_inputs.ciphertext.len());
    assert_eq!(response_inputs.plaintext.len(), response_inputs.ciphertext.len());

    let mut private_inputs = vec![];
    // TODO: Fold inputs are actually not modified, ever - We return en empty HashMap
    let fold_inputs: HashMap<String, FoldInput> = HashMap::new();

    let InitialNIVCInputs { ciphertext_digest, initial_nivc_input, headers_digest } =
      self.initial_inputs::<MAX_STACK_HEIGHT, CIRCUIT_SIZE>(
        &request_inputs.ciphertext,
        &response_inputs.ciphertext,
      )?;

    let _ = build_plaintext_authentication_circuit_inputs::<CIRCUIT_SIZE>(
      request_inputs,
      ciphertext_digest,
      &mut private_inputs,
    )?;
    // debug!("private_inputs: {:?}", private_inputs.len());

    let (_, request_body) = build_http_verification_circuit_inputs::<CIRCUIT_SIZE>(
      &request_inputs.plaintext,
      ciphertext_digest,
      &headers_digest,
      &mut private_inputs,
    )?;
    // debug!("private_inputs: {:?}", private_inputs.len());

    let _ = build_json_extraction_circuit_inputs::<CIRCUIT_SIZE>(
      &request_body,
      ciphertext_digest,
      // WARN: sending response keys for request
      (Some(&[]), Some(&self.0.response.body.json_path())),
      &mut private_inputs,
    )?;
    // debug!("private_inputs: {:?}", private_inputs.len());

    let _ = build_plaintext_authentication_circuit_inputs::<CIRCUIT_SIZE>(
      response_inputs,
      ciphertext_digest,
      &mut private_inputs,
    )?;

    // debug!("private_inputs: {:?}", private_inputs.len());
    let (_, response_body) = build_http_verification_circuit_inputs::<CIRCUIT_SIZE>(
      &response_inputs.plaintext,
      ciphertext_digest,
      &headers_digest,
      &mut private_inputs,
    )?;

    let _ = build_json_extraction_circuit_inputs::<CIRCUIT_SIZE>(
      &response_body,
      ciphertext_digest,
      (None, Some(&self.0.response.body.json_path())),
      &mut private_inputs,
    )?;

    Ok(NivcCircuitInputs { private_inputs, fold_inputs, initial_nivc_input })
  }

  /// Builds ROM for [`Manifest`] request and response.
  pub fn build_rom<const CIRCUIT_SIZE: usize>(
    &self,
    request_inputs: &EncryptionInput,
    response_inputs: &EncryptionInput,
  ) -> NIVCRom {
    let plaintext_authentication_label = String::from("PLAINTEXT_AUTHENTICATION");
    let http_verification_label = String::from("HTTP_VERIFICATION");
    let json_extraction_label = String::from("JSON_EXTRACTION");

    let mut rom = vec![];
    // ------------------- Request -------------------

    let combined_request_plaintext_length: usize =
      request_inputs.plaintext.iter().map(|x| x.len()).sum();

    // plaintext_authentication_label is duplicated `response_packets` times
    let mut rom_data = HashMap::new();
    let mut plaintext_circuit_counter = 0;
    for c in request_inputs.ciphertext.iter() {
      let circuit_count = (c.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
      for _ in 0..circuit_count {
        let plaintext_circuit =
          format!("{}_{}", plaintext_authentication_label, plaintext_circuit_counter);
        rom_data.insert(plaintext_circuit.clone(), CircuitData { opcode: 0 });
        rom.push(plaintext_circuit);
        plaintext_circuit_counter += 1;
      }
    }
    // calculate number of circuits required for request, i.e. ceil(length/CIRCUIT_SIZE)
    let request_circuit_count =
      (combined_request_plaintext_length as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
    (0..request_circuit_count).for_each(|i| {
      let http_circuit = format!("{}_{}", http_verification_label, i);
      rom_data.insert(http_circuit.clone(), CircuitData { opcode: 1 });
      rom.push(http_circuit);
    });

    let combined_request = request_inputs.plaintext.iter().flatten().cloned().collect::<Vec<u8>>();
    let request_body = compute_http_witness(&combined_request, HttpMaskType::Body);
    let request_json_circuit_count =
      (request_body.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;

    (0..request_json_circuit_count).for_each(|i| {
      let json_circuit = format!("{}_{}", json_extraction_label, i);
      rom_data.insert(json_circuit.clone(), CircuitData { opcode: 2 });
      rom.push(json_circuit);
    });

    // ------------------- Response -------------------

    let combined_response_plaintext_length: usize =
      response_inputs.plaintext.iter().map(|x| x.len()).sum();

    // plaintext_authentication_label is duplicated `response_packets` times
    for c in response_inputs.ciphertext.iter() {
      let circuit_count = (c.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
      for _ in 0..circuit_count {
        let plaintext_circuit =
          format!("{}_{}", plaintext_authentication_label, plaintext_circuit_counter);
        rom_data.insert(plaintext_circuit.clone(), CircuitData { opcode: 0 });
        rom.push(plaintext_circuit);
        plaintext_circuit_counter += 1;
      }
    }

    // calculate number of circuits required for response, i.e. ceil(length/CIRCUIT_SIZE)
    let response_circuit_count =
      (combined_response_plaintext_length as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
    (0..response_circuit_count).for_each(|i| {
      let http_circuit = format!("{}_{}", http_verification_label, i + request_circuit_count);
      rom_data.insert(http_circuit.clone(), CircuitData { opcode: 1 });
      rom.push(http_circuit);
    });

    let combined_response =
      response_inputs.plaintext.iter().flatten().cloned().collect::<Vec<u8>>();
    let response_body = compute_http_witness(&combined_response, HttpMaskType::Body);
    let response_json_circuit_count =
      (response_body.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;

    (0..response_json_circuit_count).for_each(|i| {
      let json_circuit = format!("{}_{}", json_extraction_label, i + request_json_circuit_count);
      rom_data.insert(json_circuit.clone(), CircuitData { opcode: 2 });
      rom.push(json_circuit);
    });

    NIVCRom { circuit_data: rom_data, rom }
  }
}

// TODO(Sambhav): can we remove usage of vec here?
/// encryption input for AES/CHACHA required to generate witness for the circuits
#[derive(Clone)]
pub struct EncryptionInput {
  /// 128-bit key
  pub key:        CipherSuiteKey,
  /// 96-bit IV
  pub iv:         [u8; 12],
  /// 128-bit AAD
  pub aad:        Vec<u8>,
  /// plaintext to be encrypted
  pub plaintext:  Vec<Vec<u8>>,
  /// ciphertext associated with plaintext
  pub ciphertext: Vec<Vec<u8>>,
  /// nonce sequence number
  pub seq:        u64,
}

/// TLS encryption input for request and response proving
pub struct TLSEncryption {
  /// Request encryption input
  pub request:  EncryptionInput,
  /// Response encryption input
  pub response: EncryptionInput,
}

// TODO: can remove string usage here
/// NIVC ROM containing circuit data and rom
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NIVCRom {
  /// [`CircuitData`] for each instruction
  pub circuit_data: HashMap<String, CircuitData>,
  /// NIVC ROM containing opcodes defining the computation.
  pub rom:          Vec<String>,
}

/// NIVC circuit inputs containing private inputs, fold inputs and initial nivc input
pub struct NivcCircuitInputs {
  /// private inputs to be used for each circuit defined circuit input label wise
  pub private_inputs:     Vec<HashMap<String, serde_json::Value>>,
  /// fold inputs to be used for each circuit, later expanded across folds
  pub fold_inputs:        HashMap<String, FoldInput>,
  /// initial public input
  // TODO: change this to array
  pub initial_nivc_input: [F<G1>; PUBLIC_IO_VARS],
}

/// Initial NIVC inputs
pub struct InitialNIVCInputs {
  /// Ciphertext digest
  pub ciphertext_digest:  F<G1>,
  /// Initial NIVC input
  pub initial_nivc_input: [F<G1>; PUBLIC_IO_VARS],
  /// Headers digest
  pub headers_digest:     Vec<F<G1>>,
}

/// convert bytes to u32
fn to_u32_array(input: &[u8]) -> Vec<u32> {
  // Calculate padding needed to make length divisible by 4
  let padding_needed = (4 - (input.len() % 4)) % 4;

  // Create a new vector with padding
  let padded_input =
    input.iter().chain(std::iter::repeat_n(&0, padding_needed)).copied().collect::<Vec<u8>>();

  padded_input
    .chunks(4)
    .map(|chunk| {
      // Convert 4 bytes to u32 (little-endian)
      u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
    })
    .collect()
}

/// converts array of u32 to array of bits in little endian order
fn u32_array_to_le_bits(input: &[u32]) -> Vec<Vec<u8>> {
  input
    .iter()
    .map(|&num| {
      // Convert each u32 to a vector of bits (0 or 1)
      (0..32).map(|i| ((num >> (31 - i)) & 1) as u8).collect()
    })
    .collect()
}

/// convert bytes to 32 bit array and then little endian bits
pub fn to_chacha_input(input: &[u8]) -> Vec<Vec<u8>> { u32_array_to_le_bits(&to_u32_array(input)) }

/// create nonce for CHACHA20POLY1305
pub fn make_nonce(iv: [u8; 12], seq: u64) -> [u8; 12] {
  let mut nonce = [0u8; 12];
  nonce[4..].copy_from_slice(&seq.to_be_bytes());

  nonce.iter_mut().zip(iv.iter()).for_each(|(nonce, iv)| {
    *nonce ^= *iv;
  });

  nonce
}

/// create ROM circuit data for encryption circuit from TLS inputs
///
/// ## Arguments
/// - `inputs`: [`EncryptionInput`] containing TLS key, iv, aad for encryption circuit
/// - `polynomial input`: randomised input for circuit input digest
/// - `private_inputs`: private inputs to be used in the circuit
/// - `fold_inputs`: fold inputs to be used in the circuit
///
/// ## Note:
/// - MAC is ignored from the ciphertext because circuit doesn't verify auth tag.
/// - handle different cipher suite, currently AES-GCM-128 & ChaCha20-Poly1305
fn build_plaintext_authentication_circuit_inputs<const CIRCUIT_SIZE: usize>(
  inputs: &EncryptionInput,
  polynomial_input: F<G1>,
  private_inputs: &mut Vec<HashMap<String, Value>>,
) -> Result<F<G1>, ProofError> {
  let mut plaintext_step_out = F::<G1>::ZERO;

  let key = inputs.key.as_ref();
  debug!("key: {:?}", key);
  debug!("iv: {:?}", inputs.iv);
  debug!("seq: {:?}", inputs.seq);
  debug!("aad: {:?}", inputs.aad);
  debug!("plaintext: {:?}", inputs.plaintext);
  debug!("ciphertext: {:?}", inputs.ciphertext);
  assert_eq!(key.len(), 32, "Only CHACHA20POLY1305 is supported for now");

  let counter_step = CIRCUIT_SIZE / 64;

  let mut curr_plaintext_index = 0;
  let mut prev_ciphertext_digest = F::<G1>::ZERO;
  for (plaintext_circuit_counter, (pt, ct)) in
    inputs.plaintext.iter().zip(inputs.ciphertext.iter()).enumerate()
  {
    // assert!(pt.len() <= CIRCUIT_SIZE, "Plaintext is larger than circuit size");
    assert_eq!(pt.len(), ct.len(), "Plaintext and ciphertext length mismatch");

    let padded_plaintext = ByteOrPad::pad_to_nearest_multiple(pt, CIRCUIT_SIZE);
    let nonce = make_nonce(inputs.iv, inputs.seq + plaintext_circuit_counter as u64);

    // CHACHA rom opcode with private inputs

    // add fold inputs
    // let circuit_label =
    //   format!("PLAINTEXT_AUTHENTICATION_{}", inputs.seq + plaintext_circuit_counter as u64);

    let pt_chunks = padded_plaintext.chunks(CIRCUIT_SIZE).map(|p| json!(p)).collect::<Vec<Value>>();
    let counters = (0..pt_chunks.len())
      .map(|i| json!(to_chacha_input(&[(1 + i * counter_step) as u8])))
      .collect::<Vec<Value>>();

    for i in 0..pt_chunks.len() {
      let private_input = HashMap::from([
        (String::from("key"), json!(to_chacha_input(key))),
        (String::from("nonce"), json!(to_chacha_input(&nonce))),
        (String::from("counter"), counters[i].clone()),
        (String::from("plaintext"), pt_chunks[i].clone()),
        (
          String::from("ciphertext_digest"),
          json!(BigInt::from_bytes_le(num_bigint::Sign::Plus, &polynomial_input.to_bytes())
            .to_str_radix(10)),
        ),
      ]);
      private_inputs.push(private_input);
    }

    let plaintext_digest = polynomial_digest(pt, polynomial_input, curr_plaintext_index as u64);

    prev_ciphertext_digest = data_hasher(
      &ByteOrPad::pad_to_nearest_multiple(
        &inputs.ciphertext[plaintext_circuit_counter],
        CIRCUIT_SIZE,
      ),
      prev_ciphertext_digest,
    );

    curr_plaintext_index += pt.len();
    plaintext_step_out += plaintext_digest;
  }

  Ok(plaintext_step_out - prev_ciphertext_digest)
}

/// Build HTTP verification circuit inputs
///
/// # Arguments
/// - `inputs`: input bytes
/// - `ciphertext_digest`: ciphertext digest
/// - `private_inputs`: private inputs to be used in the circuit
/// - `fold_inputs`: fold inputs to be used in the circuit
///
/// # Returns
/// - `http_body`: body of the HTTP
fn build_http_verification_circuit_inputs<const CIRCUIT_SIZE: usize>(
  plaintext_chunks: &[Vec<u8>],
  polynomial_input: F<G1>,
  headers_digest: &[F<G1>],
  private_inputs: &mut Vec<HashMap<String, Value>>,
) -> Result<(F<G1>, Vec<u8>), ProofError> {
  // pad request plaintext and ciphertext to circuit size
  let plaintext = plaintext_chunks.iter().flatten().cloned().collect::<Vec<u8>>();
  debug!("plaintext: {:?}", plaintext.len());
  debug!("plaintext: {:?}", plaintext);

  let mut main_digests =
    headers_digest.iter().map(|h| field_element_to_base10_string(*h)).collect::<Vec<_>>();
  main_digests
    .extend(std::iter::repeat_n("0".to_string(), MAX_HTTP_HEADERS + 1 - headers_digest.len()));

  // debug!("main_digests: {:?}", main_digests);

  let states = http_parse(&plaintext, polynomial_input)?;

  for (i, pt) in plaintext.chunks(CIRCUIT_SIZE).enumerate() {
    let state = if i == 0 {
      RawHttpMachine::initial_state()
    } else {
      RawHttpMachine::from(states[CIRCUIT_SIZE * i - 1])
    };
    debug!("pt: {:?}", pt.len());
    let padded_pt = ByteOrPad::pad_to_nearest_multiple(pt, CIRCUIT_SIZE);
    debug!("padded_pt: {:?}", padded_pt.len());
    private_inputs.push(HashMap::from([
      (String::from(DATA_SIGNAL_NAME), json!(padded_pt)),
      (
        String::from("ciphertext_digest"),
        json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &polynomial_input.to_bytes())
          .to_str_radix(10)]),
      ),
      (String::from("main_digests"), json!(main_digests)),
      (String::from("machine_state"), json!(state)),
    ]));
  }
  let plaintext_digest = polynomial_digest(&plaintext, polynomial_input, 0);

  // TODO (Sambhav): verify that headers digest calculated in initial input match or maybe we check
  // it in initial input

  let http_body = compute_http_witness(&plaintext, HttpMaskType::Body);
  debug!("HTTP body: {:?}", http_body.len());

  let http_body_digest = polynomial_digest(&http_body, polynomial_input, 0);

  Ok((http_body_digest - plaintext_digest, http_body))
}

/// Build JSON extraction circuit inputs
///
/// # Arguments
/// - `inputs`: valid input json bytes
/// - `polynomial_input`: randomised input for circuit input digest
/// - `keys`: JSON keys to mask
/// - `private_inputs`: private inputs to be used in the circuit
/// - `fold_inputs`: fold inputs to be used in the circuit
///
/// # Returns
/// - `masked_body`: masked body of the JSON
///
/// # Notes
/// Pads `inputs` to `CIRCUIT_SIZE` and computes the digest of the JSON key sequence.
fn build_json_extraction_circuit_inputs<const CIRCUIT_SIZE: usize>(
  inputs: &[u8],
  polynomial_input: F<G1>,
  keys: (Option<&[JsonKey]>, Option<&[JsonKey]>),
  private_inputs: &mut Vec<HashMap<String, Value>>,
) -> Result<F<G1>, ProofError> {
  assert!(keys.1.is_some());
  let response_keys = keys.1.unwrap();

  let raw_response_json_machine =
    RawJsonMachine::<MAX_STACK_HEIGHT>::from_chosen_sequence_and_input(
      polynomial_input,
      response_keys,
    )?;
  let sequence_digest = raw_response_json_machine.compress_tree_hash();

  // check request keys, if present, then return empty value
  // else compute the value digest
  let value = match keys.0 {
    Some(_) => vec![],
    None => json_value_digest::<MAX_STACK_HEIGHT>(inputs, response_keys)?,
  };
  let value_digest = polynomial_digest(&value, polynomial_input, 0);

  // no need to supply padded input as state is always from valid ascii
  debug!("inputs: {:?}", inputs.len());
  debug!("inputs: {:?}", inputs);
  let states = parse::<MAX_STACK_HEIGHT>(inputs, polynomial_input)?;
  for (i, pt) in inputs.chunks(CIRCUIT_SIZE).enumerate() {
    let state = if i == 0 {
      RawJsonMachine::initial_state()
    } else {
      RawJsonMachine::from(states[CIRCUIT_SIZE * i - 1].clone())
    };

    let state =
      state.flatten().iter().map(|f| field_element_to_base10_string(*f)).collect::<Vec<String>>();
    // debug!("state: {:?}", state);
    private_inputs.push(HashMap::from([
      (
        String::from(DATA_SIGNAL_NAME),
        json!(&ByteOrPad::pad_to_nearest_multiple(pt, CIRCUIT_SIZE)),
      ),
      (
        String::from("ciphertext_digest"),
        json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &polynomial_input.to_bytes())
          .to_str_radix(10)]),
      ),
      (
        String::from("sequence_digest"),
        json!([BigInt::from_bytes_le(num_bigint::Sign::Plus, &sequence_digest.to_bytes())
          .to_str_radix(10)]),
      ),
      (
        String::from("value_digest"),
        json!(
          BigInt::from_bytes_le(num_bigint::Sign::Plus, &value_digest.to_bytes()).to_str_radix(10)
        ),
      ),
      (String::from("state"), json!(state)),
    ]));
  }

  let data_digest = polynomial_digest(inputs, polynomial_input, 0);

  Ok(value_digest - data_digest)
}

/// Compute ciphertext digest
pub fn compute_ciphertext_digest<const CIRCUIT_SIZE: usize>(
  request_ciphertext: &[Vec<u8>],
  response_ciphertext: &[Vec<u8>],
) -> F<G1> {
  let padded_request_ciphertext = request_ciphertext
    .iter()
    .map(|c| ByteOrPad::pad_to_nearest_multiple(c, CIRCUIT_SIZE))
    .collect::<Vec<Vec<ByteOrPad>>>();
  let padded_response_ciphertext = response_ciphertext
    .iter()
    .map(|c| ByteOrPad::pad_to_nearest_multiple(c, CIRCUIT_SIZE))
    .collect::<Vec<Vec<ByteOrPad>>>();

  let mut ciphertext_digest = F::<G1>::ZERO;
  padded_request_ciphertext
    .iter()
    .for_each(|c| ciphertext_digest = data_hasher(c, ciphertext_digest));
  padded_response_ciphertext
    .iter()
    .for_each(|c| ciphertext_digest = data_hasher(c, ciphertext_digest));

  ciphertext_digest
}

#[cfg(test)]
mod tests {
  use web_prover_core::test_utils::TEST_MANIFEST;

  use super::*;
  use crate::tests::inputs::{
    complex_manifest, complex_request_inputs, complex_response_inputs, simple_request_inputs,
    simple_response_inputs,
  };

  fn simple_inputs() -> (EncryptionInput, EncryptionInput) {
    (simple_request_inputs(), simple_response_inputs())
  }

  fn complex_inputs() -> (EncryptionInput, EncryptionInput) {
    (complex_request_inputs(), complex_response_inputs())
  }

  fn assert_rom_from_inputs<const CIRCUIT_SIZE: usize>(
    manifest: OrigoManifest,
    request_inputs: EncryptionInput,
    response_inputs: EncryptionInput,
  ) {
    let NivcCircuitInputs { fold_inputs, private_inputs, .. } =
      manifest.build_inputs::<CIRCUIT_SIZE>(&request_inputs, &response_inputs).unwrap();
    let NIVCRom { circuit_data: rom_data, rom } =
      manifest.build_rom::<CIRCUIT_SIZE>(&request_inputs, &response_inputs);

    // request:
    // plaintext_authentication (multiple chunks)
    // + http verification (divide into CIRCUIT_SIZE)
    // response:
    // plaintext_authentication (multiple chunks)
    // + http verification (divide into CIRCUIT_SIZE)
    // + json extraction (body divide into CIRCUIT_SIZE)
    println!("rom: {:?}", rom);
    assert_eq!(rom.len(), rom_data.len());

    let plaintext_combined =
      request_inputs.plaintext.iter().flatten().cloned().collect::<Vec<u8>>();
    let mut plaintext_circuit_count = 0;
    for c in request_inputs.ciphertext.iter() {
      let circuit_count = (c.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
      for _ in 0..circuit_count {
        let plaintext_circuit = format!("PLAINTEXT_AUTHENTICATION_{}", plaintext_circuit_count);
        assert_eq!(rom_data.get(&plaintext_circuit).unwrap().opcode, 0);
        plaintext_circuit_count += 1;
      }
    }

    let http_circuit_count =
      (plaintext_combined.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;

    // assert plaintext authentication inputs
    let plaintext_authentication_len = 0;
    assert_eq!(rom[plaintext_authentication_len], String::from("PLAINTEXT_AUTHENTICATION_0"));
    assert!(private_inputs[plaintext_authentication_len].contains_key("counter"));
    assert!(private_inputs[plaintext_authentication_len].contains_key("nonce"));
    assert!(private_inputs[plaintext_authentication_len].contains_key("key"));
    assert!(private_inputs[plaintext_authentication_len].contains_key("plaintext"));

    // assert http parse inputs
    let http_instruction_len = plaintext_circuit_count;
    assert_eq!(rom[http_instruction_len], String::from("HTTP_VERIFICATION_0"));
    assert!(private_inputs[http_instruction_len].contains_key("main_digests"));
    assert!(private_inputs[http_instruction_len].contains_key("ciphertext_digest"));
    assert!(private_inputs[http_instruction_len].contains_key("data"));

    let request_body = compute_http_witness(&plaintext_combined, HttpMaskType::Body);

    let json_circuit_count = (request_body.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
    if !request_body.is_empty() {
      // assert json extraction inputs
      let json_instruction_len = plaintext_circuit_count + http_circuit_count;
      assert_eq!(rom[json_instruction_len], String::from("JSON_EXTRACTION_0"));
      assert!(private_inputs[json_instruction_len].contains_key("ciphertext_digest"));
      assert!(private_inputs[json_instruction_len].contains_key("data"));
      assert!(private_inputs[json_instruction_len].contains_key("sequence_digest"));
      assert!(private_inputs[json_instruction_len].contains_key("value_digest"));
      assert!(private_inputs[json_instruction_len].contains_key("state"));
    }

    // assert plaintext authentication inputs
    let plaintext_authentication_len =
      plaintext_circuit_count + http_circuit_count + json_circuit_count;
    assert_eq!(
      rom[plaintext_authentication_len],
      format!("PLAINTEXT_AUTHENTICATION_{}", plaintext_circuit_count)
    );

    let response_combined =
      response_inputs.plaintext.iter().flatten().cloned().collect::<Vec<u8>>();
    let mut response_plaintext_circuit_count = plaintext_circuit_count;
    for c in response_inputs.ciphertext.iter() {
      let circuit_count = (c.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize;
      for _ in 0..circuit_count {
        let plaintext_circuit =
          format!("PLAINTEXT_AUTHENTICATION_{}", response_plaintext_circuit_count);
        assert_eq!(rom_data.get(&plaintext_circuit).unwrap().opcode, 0);
        response_plaintext_circuit_count += 1;
      }
    }
    let response_http_circuit_count =
      (response_combined.len() as f64 / CIRCUIT_SIZE as f64).ceil() as usize + http_circuit_count;

    // check final circuit is extract
    let json_instruction_len =
      response_plaintext_circuit_count + response_http_circuit_count + json_circuit_count;
    assert_eq!(rom[json_instruction_len], format!("JSON_EXTRACTION_{}", json_circuit_count));
    assert!(private_inputs[json_instruction_len].contains_key("ciphertext_digest"));
    assert!(private_inputs[json_instruction_len].contains_key("data"));
    assert!(private_inputs[json_instruction_len].contains_key("sequence_digest"));
    assert!(private_inputs[json_instruction_len].contains_key("value_digest"));
    assert!(private_inputs[json_instruction_len].contains_key("state"));

    assert!(fold_inputs.is_empty());
  }

  #[test]
  fn test_rom_from_inputs() {
    let manifest: Manifest = serde_json::from_str(TEST_MANIFEST).unwrap();
    let (request_inputs, response_inputs) = simple_inputs();
    assert_rom_from_inputs::<512>(manifest.into(), request_inputs, response_inputs);

    let (request_inputs, response_inputs) = complex_inputs();
    assert_rom_from_inputs::<512>(complex_manifest().into(), request_inputs, response_inputs);
  }

  #[test]
  fn test_to_u32_array() {
    // empty
    let input: Vec<u8> = vec![];
    let result = to_u32_array(&input);
    assert_eq!(result.len(), 0);

    // two incomplete u32
    let input = vec![1, 2, 3, 4, 5];
    let result = to_u32_array(&input);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], u32::from_le_bytes([1, 2, 3, 4]));
    assert_eq!(result[1], u32::from_le_bytes([5, 0, 0, 0]));

    // two complete u32
    let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let result = to_u32_array(&input);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], u32::from_le_bytes([1, 2, 3, 4]));
    assert_eq!(result[1], u32::from_le_bytes([5, 6, 7, 8]));
  }

  #[test]
  fn test_u32_array_to_le_bits() {
    // basic
    let input = vec![0x80000000]; // Most significant bit set
    let result = u32_array_to_le_bits(&input);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].len(), 32);
    assert_eq!(result[0][0], 1); // First bit should be 1
    assert_eq!(result[0][1..].iter().sum::<u8>(), 0); // Rest should be 0

    // multiple small numbers
    let input = vec![0x1, 0x2]; // Two small numbers
    let result = u32_array_to_le_bits(&input);
    assert_eq!(result.len(), 2);

    // First number (0x1) should have only the last bit set
    assert_eq!(result[0][31], 1);
    assert_eq!(result[0][..31].iter().sum::<u8>(), 0);

    // Second number (0x2) should have the second-to-last bit set
    assert_eq!(result[1][30], 1);
    assert_eq!(result[1][..30].iter().chain(result[1][31..].iter()).sum::<u8>(), 0);

    // empty
    let input: Vec<u32> = vec![];
    let result = u32_array_to_le_bits(&input);
    assert_eq!(result.len(), 0);

    // all bits set
    let input = vec![0xFFFFFFFF];
    let result = u32_array_to_le_bits(&input);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].iter().sum::<u8>(), 32); // All bits should be 1

    // property-based test
    let original = vec![0x12345678, 0x9ABCDEF0];
    let bits = u32_array_to_le_bits(&original);

    // Convert bits back to u32s
    let reconstructed: Vec<u32> = bits
      .iter()
      .map(|bit_vec| {
        bit_vec.iter().enumerate().fold(0u32, |acc, (i, &bit)| acc | ((bit as u32) << (31 - i)))
      })
      .collect();

    assert_eq!(original, reconstructed);
  }

  #[test]
  fn test_to_chacha_input_integration() {
    // empty input
    let input: Vec<u8> = vec![];
    let result = to_chacha_input(&input);
    assert_eq!(result.len(), 0);

    // smal input
    let input = vec![0xFF, 0x00, 0xAA, 0x55]; // Test pattern
    let result = to_chacha_input(&input);

    assert_eq!(result.len(), 1); // Should produce one u32
    assert_eq!(result[0].len(), 32); // Each u32 produces 32 bits

    // Verify the bit pattern matches expected transformation
    let expected_u32 = u32::from_le_bytes([0xFF, 0x00, 0xAA, 0x55]);
    let expected_bits: Vec<u8> = (0..32).map(|i| ((expected_u32 >> (31 - i)) & 1) as u8).collect();
    assert_eq!(result[0], expected_bits);

    // large input
    let counter_u32 = [1];
    let res = to_u32_array(&counter_u32);
    assert_eq!(res, [1]);

    let counter_back = u32_array_to_le_bits(&res);
    assert_eq!(counter_back, vec![vec![
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      1
    ]]);

    let http_u32 = "HTTP".as_bytes();
    assert_eq!(to_u32_array(http_u32), [1347703880]);

    let http_bits = u32_array_to_le_bits(&to_u32_array(http_u32));
    assert_eq!(http_bits, [[
      0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0,
      0
    ]]);
  }
}
