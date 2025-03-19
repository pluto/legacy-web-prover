// logic common to wasm32 and native

use http_body_util::BodyExt;
use hyper::{body::Bytes, Request};
use serde::{Deserialize, Serialize};
use spansy::{
  http::Response,
  json::{parse, JsonValue},
  Spanned,
};
use hyper::header;
pub use tlsn_core::attestation::Attestation;
use tlsn_core::{
  presentation::Presentation, request::RequestConfig, transcript::TranscriptCommitConfig,
  CryptoProvider, Secrets,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{state::Closed, Prover};
use tracing::debug;
use utils::range::{RangeSet, ToRangeSet};
use web_proof_circuits_witness_generator::json::JsonKey;
use web_prover_core::manifest::Manifest;

use crate::{errors, SignedVerificationReply};

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsnProof {
  pub proof:      Presentation,
  pub sign_reply: Option<SignedVerificationReply>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsnVerifyBody {
  pub proof:    Presentation,
  pub manifest: Manifest,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
  pub server_name: String,
  pub time:        u64,
  pub sent:        String,
  pub recv:        String,
}

/// compute range set for masking based on json path from manifest
/// # Arguments
/// - `response`: response from the server
/// - `keys`: json path from manifest
/// # Returns
/// - range set for masking
/// # Errors
/// - if response body is missing
/// - if content span is empty
/// - if key is not found in response body
fn compute_json_mask_range_set(
  response: &Response,
  keys: &[JsonKey],
) -> Result<Vec<RangeSet<usize>>, errors::ClientErrors> {
  let response_body = match &response.body {
    Some(body) => body,
    None => return Err(errors::ClientErrors::Other("Response body is missing".to_string())),
  };

  // commit to keys specified in manifest
  // commit values specified in manifest

  let content_span = response_body.content.span();
  let initial_index = match content_span.indices().min() {
    Some(index) => index,
    None => return Err(errors::ClientErrors::Other("Content span is empty".to_string())),
  };

  let mut content_value = parse(content_span.clone().to_bytes()).unwrap();
  content_value.offset(initial_index);

  let mut range_sets = Vec::new();
  for key in keys {
    let key = match key {
      JsonKey::String(s) => s.clone(),
      JsonKey::Num(n) => n.to_string(),
    };

    match content_value {
      JsonValue::Object(ref v) =>
        for kv in v.elems.iter() {
          if key.as_str() == kv.key {
            range_sets.push(kv.key.to_range_set());
          }
        },
      JsonValue::Array(ref v) => {
        range_sets.push(v.without_values());
      },
      _ => {},
    };
    let key_span = content_value.get(key.as_str());
    match key_span {
      Some(key_span) => {
        content_value = key_span.clone();
      },
      None =>
        return Err(errors::ClientErrors::Other(format!("Key {} not found in response body", key))),
    }
  }
  range_sets.push(content_value.to_range_set());
  Ok(range_sets)
}

pub async fn notarize(
  prover: Prover<Closed>,
  manifest: &Manifest,
) -> Result<Presentation, errors::ClientErrors> {
  let mut prover = prover.start_notarize();

  let (sent_len, recv_len) = prover.transcript().len();
  let mut builder = TranscriptCommitConfig::builder(prover.transcript());

  builder.commit_sent(&(0..sent_len)).unwrap();
  builder.commit_recv(&(0..recv_len)).unwrap();

  let commit_config = builder.build().unwrap();

  prover.transcript_commit(commit_config);

  let request = RequestConfig::builder().build().unwrap();

  let (attestation, secrets) = prover.finalize(&request).await.unwrap();

  let presentation = present(&Some(manifest.clone()), attestation, secrets).await?;
  Ok(presentation)
}

pub async fn present(
  manifest: &Option<Manifest>,
  attestation: Attestation,
  secrets: Secrets,
) -> Result<Presentation, errors::ClientErrors> {
  // get the manifest
  let manifest = match manifest {
    Some(manifest) => manifest,
    None => return Err(errors::ClientErrors::Other("Manifest is missing".to_string())),
  };

  // Parse the HTTP transcript.
  let transcript = HttpTranscript::parse(secrets.transcript())?;

  // Build a transcript proof.
  let mut builder = secrets.transcript_proof_builder();

  let request = &transcript.requests[0];
  // Reveal the structure of the request without the headers or body.
  builder.reveal_sent(&request.without_data())?;
  // Reveal the request target.
  builder.reveal_sent(&request.request.target)?;
  // Reveal all headers except the values of User-Agent and Authorization.
  for header in &request.headers {
    if !(header.name.as_str().eq_ignore_ascii_case(header::USER_AGENT.as_str())
      || header.name.as_str().eq_ignore_ascii_case(header::AUTHORIZATION.as_str()))
    {
      builder.reveal_sent(header)?;
    } else {
      builder.reveal_sent(&header.without_value())?;
    }
  }

  // Reveal only parts of the response
  let response = &transcript.responses[0];
  builder.reveal_recv(&response.without_data())?;
  for header in &response.headers {
    builder.reveal_recv(header)?;
  }

  let content = &response.body.as_ref().unwrap().content;
  match content {
    tlsn_formats::http::BodyContent::Json(json) => {
      // For experimentation, reveal the entire response or just a selection
      let reveal_all = false;
      if reveal_all {
        builder.reveal_recv(response)?;
      } else {
        builder.reveal_recv(json.get("id").unwrap())?;
        builder.reveal_recv(json.get("information.name").unwrap())?;
        builder.reveal_recv(json.get("meta.version").unwrap())?;
      }
    },
    tlsn_formats::http::BodyContent::Unknown(span) => {
      builder.reveal_recv(span)?;
    },
    _ => {},
  }

  let transcript_proof = builder.build()?;

  // Use default crypto provider to build the presentation.
  let provider = CryptoProvider::default();

  let mut builder = attestation.presentation_builder(&provider);

  builder.identity_proof(secrets.identity_proof()).transcript_proof(transcript_proof);

  let presentation: Presentation = builder.build()?;

  Ok(presentation)
}

pub async fn send_request(
  mut request_sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>,
  request: Request<http_body_util::Full<Bytes>>,
) {
  // TODO: Clean up this logging and error handling
  match request_sender.send_request(request).await {
    Ok(response) => {
      let status = response.status();
      let headers = response.headers().clone();
      debug!(
        "Response with status code {:?}:\nHeaders: {:?}\n\nBody:\n{}",
        status,
        headers,
        body_to_string(response).await
      );
      assert!(status.is_success()); // status is 200-299
    },
    Err(e) if e.is_incomplete_message() => println!("Response: IncompleteMessage (ignored)"), /* TODO is this safe to ignore */
    Err(e) => panic!("{:?}", e),
  };
}

async fn body_to_string(res: hyper::Response<hyper::body::Incoming>) -> String {
  let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
  String::from_utf8(body_bytes.to_vec()).unwrap()
}
