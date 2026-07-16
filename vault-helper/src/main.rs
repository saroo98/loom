use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use keyring::v1::Entry;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::io::{self, Read};
use x25519_dalek::{PublicKey as ExchangePublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;
const MAX_INPUT: u64 = loom_vault::MAX_INPUT as u64;
const LEGACY_KDF_M_COST: u32 = 19 * 1024;
const LEGACY_KDF_T_COST: u32 = 2;
const CURRENT_KDF_M_COST: u32 = 64 * 1024;
const CURRENT_KDF_T_COST: u32 = 3;
const KDF_P_COST: u32 = 1;
const KDF_OUTPUT_BYTES: usize = 32;

fn kdf_value(memory_kib: u32, iterations: u32) -> Value {
    json!({
        "algorithm": "argon2id",
        "version": 19,
        "memory_kib": memory_kib,
        "iterations": iterations,
        "parallelism": KDF_P_COST,
        "output_bytes": KDF_OUTPUT_BYTES,
    })
}

fn kdf_params(value: &Value) -> Result<(u32, u32), String> {
    exact_fields(
        value,
        &[
            "algorithm",
            "version",
            "memory_kib",
            "iterations",
            "parallelism",
            "output_bytes",
        ],
    )?;
    let algorithm = field(value, "algorithm")?;
    let version = value.get("version").and_then(Value::as_u64);
    let memory = value.get("memory_kib").and_then(Value::as_u64);
    let iterations = value.get("iterations").and_then(Value::as_u64);
    let parallelism = value.get("parallelism").and_then(Value::as_u64);
    let output = value.get("output_bytes").and_then(Value::as_u64);
    let candidate = (
        u32::try_from(memory.unwrap_or(0)).unwrap_or(0),
        u32::try_from(iterations.unwrap_or(0)).unwrap_or(0),
    );
    let allowed = candidate == (LEGACY_KDF_M_COST, LEGACY_KDF_T_COST)
        || candidate == (CURRENT_KDF_M_COST, CURRENT_KDF_T_COST);
    if algorithm != "argon2id"
        || version != Some(19)
        || parallelism != Some(u64::from(KDF_P_COST))
        || output != Some(KDF_OUTPUT_BYTES as u64)
        || !allowed
    {
        return Err("passphrase KDF descriptor is unsupported or exceeds bounds".to_string());
    }
    Ok(candidate)
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
) -> Result<[u8; 32], String> {
    let params = Params::new(memory_kib, iterations, KDF_P_COST, Some(KDF_OUTPUT_BYTES))
        .map_err(|_| "passphrase KDF parameters are invalid".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| "passphrase derivation failed".to_string())?;
    Ok(key)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid field: {name}"))
}

fn decoded(value: &Value, name: &str, max: usize) -> Result<Vec<u8>, String> {
    let result = B64
        .decode(field(value, name)?)
        .map_err(|_| format!("invalid base64 field: {name}"))?;
    if result.len() > max {
        return Err(format!("field exceeds bound: {name}"));
    }
    Ok(result)
}

fn key32(value: &Value, name: &str) -> Result<[u8; 32], String> {
    let mut bytes = decoded(value, name, 32)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(format!("{name} must contain 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn seal_with_key(mut key: [u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "authenticated encryption failed".to_string())?;
    let mut output = Vec::with_capacity(nonce.len() + sealed.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&sealed);
    key.zeroize();
    nonce.zeroize();
    Ok(output)
}

fn open_with_key(mut key: [u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 40 {
        key.zeroize();
        return Err("ciphertext is truncated".to_string());
    }
    let cipher = XChaCha20Poly1305::new((&key).into());
    let result = cipher
        .decrypt(
            XNonce::from_slice(&ciphertext[..24]),
            Payload {
                msg: &ciphertext[24..],
                aad,
            },
        )
        .map_err(|_| "authentication failed".to_string());
    key.zeroize();
    result
}

fn pair_key(secret: [u8; 32], public: [u8; 32], aad: &[u8]) -> Result<[u8; 32], String> {
    let mut secret = StaticSecret::from(secret);
    let public = ExchangePublicKey::from(public);
    let mut shared = secret.diffie_hellman(&public).to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(b"loom-pair-v1"), &shared);
    let mut key = [0u8; 32];
    hkdf.expand(aad, &mut key)
        .map_err(|_| "pairing key derivation failed".to_string())?;
    shared.zeroize();
    secret.zeroize();
    Ok(key)
}

fn recovery_key(phrase: &str, aad: &[u8]) -> Result<[u8; 32], String> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|_| "recovery phrase is invalid".to_string())?;
    if mnemonic.word_count() != 24 {
        return Err("recovery phrase must contain 24 words".to_string());
    }
    let mut entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        entropy.zeroize();
        return Err("recovery phrase entropy is invalid".to_string());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(b"loom-recovery-v1"), &entropy);
    let mut key = [0u8; 32];
    hkdf.expand(aad, &mut key)
        .map_err(|_| "recovery key derivation failed".to_string())?;
    entropy.zeroize();
    Ok(key)
}

fn exact_fields(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "request must be an object".to_string())?;
    if object.len() != allowed.len() || !object.keys().all(|key| allowed.contains(&key.as_str())) {
        return Err("request has unknown or missing fields".to_string());
    }
    Ok(())
}

fn keyring_entry(value: &Value) -> Result<Entry, String> {
    let owner = field(value, "owner_vault_id")?;
    if owner.len() != 36
        || owner.bytes().enumerate().any(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                .then_some(byte != b'-')
                .unwrap_or(!byte.is_ascii_hexdigit())
        })
    {
        return Err("owner vault identity is invalid".to_string());
    }
    Entry::new("org.loom.owner-vault", owner)
        .map_err(|_| "secure OS key store is unavailable".to_string())
}

fn execute(value: &Value) -> Result<Value, String> {
    match field(value, "op")? {
        "generate-keys" => {
            exact_fields(value, &["op"])?;
            let mut master = [0u8; 32];
            OsRng.fill_bytes(&mut master);
            let signing = SigningKey::generate(&mut OsRng);
            let exchange = StaticSecret::random_from_rng(OsRng);
            let exchange_public = ExchangePublicKey::from(&exchange);
            let output = json!({
                "master_key": B64.encode(master),
                "signing_key": B64.encode(signing.to_bytes()),
                "signing_public": B64.encode(signing.verifying_key().to_bytes()),
                "exchange_secret": B64.encode(exchange.to_bytes()),
                "exchange_public": B64.encode(exchange_public.as_bytes()),
            });
            master.zeroize();
            Ok(output)
        }
        "key-store-set" => {
            exact_fields(value, &["op", "owner_vault_id", "secret"])?;
            let mut secret = decoded(value, "secret", 4096)?;
            if secret.len() < 64 {
                secret.zeroize();
                return Err("vault key material is incomplete".to_string());
            }
            let result = keyring_entry(value)?
                .set_secret(&secret)
                .map_err(|_| "secure OS key store refused the write".to_string());
            secret.zeroize();
            result?;
            Ok(json!({"stored": true}))
        }
        "key-store-get" => {
            exact_fields(value, &["op", "owner_vault_id"])?;
            let mut secret = keyring_entry(value)?
                .get_secret()
                .map_err(|_| "vault key material is unavailable".to_string())?;
            if secret.len() < 64 || secret.len() > 4096 {
                secret.zeroize();
                return Err("stored vault key material is invalid".to_string());
            }
            let output = json!({"secret": B64.encode(&secret)});
            secret.zeroize();
            Ok(output)
        }
        "key-store-delete" => {
            exact_fields(value, &["op", "owner_vault_id"])?;
            keyring_entry(value)?
                .delete_credential()
                .map_err(|_| "secure OS key store refused the deletion".to_string())?;
            Ok(json!({"deleted": true}))
        }
        "seal" => {
            exact_fields(value, &["op", "key", "plaintext", "aad"])?;
            let key = key32(value, "key")?;
            let mut plaintext = decoded(value, "plaintext", 1024 * 1024)?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let result = seal_with_key(key, &plaintext, &aad)?;
            plaintext.zeroize();
            Ok(json!({"ciphertext": B64.encode(result)}))
        }
        "open" => {
            exact_fields(value, &["op", "key", "ciphertext", "aad"])?;
            let key = key32(value, "key")?;
            let ciphertext = decoded(value, "ciphertext", 1024 * 1024 + 40)?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let mut result = open_with_key(key, &ciphertext, &aad)?;
            let output = json!({"plaintext": B64.encode(&result)});
            result.zeroize();
            Ok(output)
        }
        "sign" => {
            exact_fields(value, &["op", "signing_key", "message"])?;
            let mut secret = key32(value, "signing_key")?;
            let signing = SigningKey::from_bytes(&secret);
            let message = decoded(value, "message", 1024 * 1024)?;
            let signature = signing.sign(&message);
            secret.zeroize();
            Ok(json!({"signature": B64.encode(signature.to_bytes())}))
        }
        "verify" => {
            exact_fields(value, &["op", "public_key", "message", "signature"])?;
            let public = key32(value, "public_key")?;
            let verifying = VerifyingKey::from_bytes(&public)
                .map_err(|_| "public key is invalid".to_string())?;
            let message = decoded(value, "message", 1024 * 1024)?;
            let signature_bytes = decoded(value, "signature", 64)?;
            if signature_bytes.len() != 64 {
                return Err("signature must contain 64 bytes".to_string());
            }
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|_| "signature is invalid".to_string())?;
            Ok(json!({"valid": verifying.verify(&message, &signature).is_ok()}))
        }
        "public-key" => {
            exact_fields(value, &["op", "signing_key"])?;
            let mut secret = key32(value, "signing_key")?;
            let signing = SigningKey::from_bytes(&secret);
            let output = json!({"public_key": B64.encode(signing.verifying_key().to_bytes())});
            secret.zeroize();
            Ok(output)
        }
        "blind-index" => {
            exact_fields(value, &["op", "key", "label", "value"])?;
            let mut key = key32(value, "key")?;
            let label = field(value, "label")?.as_bytes();
            let input = field(value, "value")?.as_bytes();
            if label.is_empty() || label.len() > 128 || input.len() > 64 * 1024 {
                key.zeroize();
                return Err("blind-index input exceeds bound".to_string());
            }
            let hkdf = Hkdf::<Sha256>::new(Some(b"loom-blind-index-v1"), &key);
            let mut subkey = [0u8; 32];
            hkdf.expand(label, &mut subkey)
                .map_err(|_| "blind-index derivation failed".to_string())?;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&subkey)
                .map_err(|_| "blind-index initialization failed".to_string())?;
            mac.update(input);
            let tag = hex::encode(mac.finalize().into_bytes());
            key.zeroize();
            subkey.zeroize();
            Ok(json!({"tag": tag}))
        }
        "pair-seal" => {
            exact_fields(
                value,
                &["op", "receiver_public", "signing_key", "plaintext", "aad"],
            )?;
            let receiver_public = key32(value, "receiver_public")?;
            let mut ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            let ephemeral_public = ExchangePublicKey::from(&ephemeral_secret);
            let key = pair_key(
                ephemeral_secret.to_bytes(),
                receiver_public,
                &decoded(value, "aad", 64 * 1024)?,
            )?;
            ephemeral_secret.zeroize();
            let mut plaintext = decoded(value, "plaintext", 1024 * 1024)?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let ciphertext = seal_with_key(key, &plaintext, &aad)?;
            plaintext.zeroize();
            let mut signing_secret = key32(value, "signing_key")?;
            let signing = SigningKey::from_bytes(&signing_secret);
            let mut signed = Vec::with_capacity(aad.len() + 1 + ciphertext.len());
            signed.extend_from_slice(&aad);
            signed.push(0);
            signed.extend_from_slice(&ciphertext);
            let signature = signing.sign(&signed);
            signing_secret.zeroize();
            Ok(json!({
                "ciphertext": B64.encode(ciphertext),
                "sender_exchange_public": B64.encode(ephemeral_public.as_bytes()),
                "sender_signing_public": B64.encode(signing.verifying_key().to_bytes()),
                "signature": B64.encode(signature.to_bytes())
            }))
        }
        "pair-open" => {
            exact_fields(
                value,
                &[
                    "op",
                    "receiver_secret",
                    "sender_exchange_public",
                    "sender_signing_public",
                    "ciphertext",
                    "signature",
                    "aad",
                ],
            )?;
            let receiver_secret = key32(value, "receiver_secret")?;
            let sender_exchange_public = key32(value, "sender_exchange_public")?;
            let sender_signing_public = key32(value, "sender_signing_public")?;
            let verifying = VerifyingKey::from_bytes(&sender_signing_public)
                .map_err(|_| "sender signing key is invalid".to_string())?;
            let ciphertext = decoded(value, "ciphertext", 1024 * 1024 + 40)?;
            let signature_bytes = decoded(value, "signature", 64)?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|_| "pairing signature is invalid".to_string())?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let mut signed = Vec::with_capacity(aad.len() + 1 + ciphertext.len());
            signed.extend_from_slice(&aad);
            signed.push(0);
            signed.extend_from_slice(&ciphertext);
            verifying
                .verify(&signed, &signature)
                .map_err(|_| "pairing signature authentication failed".to_string())?;
            let key = pair_key(receiver_secret, sender_exchange_public, &aad)?;
            let mut plaintext = open_with_key(key, &ciphertext, &aad)?;
            let output = json!({"plaintext": B64.encode(&plaintext)});
            plaintext.zeroize();
            Ok(output)
        }
        "generate-recovery" => {
            exact_fields(value, &["op"])?;
            let mnemonic = Mnemonic::generate_in(Language::English, 24)
                .map_err(|_| "recovery generation failed".to_string())?;
            let mut entropy = mnemonic.to_entropy();
            let output = json!({"phrase": mnemonic.to_string(), "secret": B64.encode(&entropy)});
            entropy.zeroize();
            Ok(output)
        }
        "recovery-wrap" => {
            exact_fields(value, &["op", "phrase", "plaintext", "aad"])?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let key = recovery_key(field(value, "phrase")?, &aad)?;
            let mut plaintext = decoded(value, "plaintext", 1024 * 1024)?;
            let ciphertext = seal_with_key(key, &plaintext, &aad)?;
            plaintext.zeroize();
            Ok(json!({"ciphertext": B64.encode(ciphertext)}))
        }
        "recovery-open" => {
            exact_fields(value, &["op", "phrase", "ciphertext", "aad"])?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let key = recovery_key(field(value, "phrase")?, &aad)?;
            let ciphertext = decoded(value, "ciphertext", 1024 * 1024 + 40)?;
            let mut plaintext = open_with_key(key, &ciphertext, &aad)?;
            let output = json!({"plaintext": B64.encode(&plaintext)});
            plaintext.zeroize();
            Ok(output)
        }
        "passphrase-wrap" => {
            let supplied_kdf = value.get("kdf");
            if supplied_kdf.is_some() {
                exact_fields(value, &["op", "passphrase", "plaintext", "aad", "kdf"])?;
            } else {
                exact_fields(value, &["op", "passphrase", "plaintext", "aad"])?;
            }
            let passphrase = field(value, "passphrase")?;
            if passphrase.len() < 12 || passphrase.len() > 1024 {
                return Err("passphrase length is invalid".to_string());
            }
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let kdf = supplied_kdf
                .cloned()
                .unwrap_or_else(|| kdf_value(CURRENT_KDF_M_COST, CURRENT_KDF_T_COST));
            let (memory_kib, iterations) = kdf_params(&kdf)?;
            let key = derive_passphrase_key(passphrase, &salt, memory_kib, iterations)?;
            let mut plaintext = decoded(value, "plaintext", 1024 * 1024)?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let sealed = seal_with_key(key, &plaintext, &aad)?;
            plaintext.zeroize();
            Ok(json!({"kdf": kdf, "salt": B64.encode(salt), "ciphertext": B64.encode(sealed)}))
        }
        "passphrase-open" => {
            exact_fields(
                value,
                &["op", "passphrase", "salt", "ciphertext", "aad", "kdf"],
            )?;
            let passphrase = field(value, "passphrase")?;
            if passphrase.len() < 12 || passphrase.len() > 1024 {
                return Err("passphrase length is invalid".to_string());
            }
            let salt = decoded(value, "salt", 16)?;
            if salt.len() != 16 {
                return Err("passphrase salt is invalid".to_string());
            }
            let (memory_kib, iterations) = kdf_params(
                value
                    .get("kdf")
                    .ok_or_else(|| "missing KDF descriptor".to_string())?,
            )?;
            let key = derive_passphrase_key(passphrase, &salt, memory_kib, iterations)?;
            let ciphertext = decoded(value, "ciphertext", 1024 * 1024 + 40)?;
            let aad = decoded(value, "aad", 64 * 1024)?;
            let mut plaintext = open_with_key(key, &ciphertext, &aad)?;
            let output = json!({"plaintext": B64.encode(&plaintext)});
            plaintext.zeroize();
            Ok(output)
        }
        _ => Err("unsupported operation".to_string()),
    }
}

fn main() {
    let result = (|| -> Result<Value, String> {
        let mut input = String::new();
        io::stdin()
            .take(MAX_INPUT + 1)
            .read_to_string(&mut input)
            .map_err(|_| "cannot read request".to_string())?;
        if input.len() as u64 > MAX_INPUT {
            return Err("request exceeds bound".to_string());
        }
        let request = loom_vault::parse_bounded_request(input.as_bytes())?;
        loom_vault::validate_crypto_envelope(&request)?;
        execute(&request)
    })();
    let mut output = Map::new();
    let mut failed = false;
    match result {
        Ok(Value::Object(values)) => {
            output.insert("ok".to_string(), Value::Bool(true));
            output.extend(values);
        }
        Ok(_) => {
            failed = true;
            output.insert("ok".to_string(), Value::Bool(false));
            output.insert(
                "error".to_string(),
                Value::String("invalid helper result".to_string()),
            );
        }
        Err(error) => {
            failed = true;
            output.insert("ok".to_string(), Value::Bool(false));
            output.insert("error".to_string(), Value::String(error));
        }
    }
    println!("{}", Value::Object(output));
    if failed {
        std::process::exit(2);
    }
}
