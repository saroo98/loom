use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::Value;

pub const MAX_INPUT: usize = 2 * 1024 * 1024;

pub fn parse_bounded_request(input: &[u8]) -> Result<Value, String> {
    if input.len() > MAX_INPUT {
        return Err("request exceeds bound".to_string());
    }
    let text = std::str::from_utf8(input).map_err(|_| "request is not UTF-8".to_string())?;
    let value: Value =
        serde_json::from_str(text).map_err(|_| "request is not valid JSON".to_string())?;
    if !value.is_object() {
        return Err("request must be a JSON object".to_string());
    }
    Ok(value)
}

pub fn validate_crypto_envelope(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "request must be a JSON object".to_string())?;
    if object.len() > 16 {
        return Err("request has too many fields".to_string());
    }
    for (name, field) in object {
        if name.len() > 64 {
            return Err("request field name exceeds bound".to_string());
        }
        if let Some(text) = field.as_str() {
            if text.len() > MAX_INPUT {
                return Err("request field exceeds bound".to_string());
            }
            if matches!(name.as_str(), "ciphertext" | "signature" | "aad" | "salt")
                && B64.decode(text).is_err()
            {
                return Err(format!("{name} is not valid base64"));
            }
        }
    }
    Ok(())
}

pub fn validate_learning_event_v3(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "learning event must be an object".to_string())?;
    if object.len() > 32 {
        return Err("learning event has too many fields".to_string());
    }
    if object.get("payload_schema_version").and_then(Value::as_u64) != Some(3) {
        return Err("learning event is not payload v3".to_string());
    }
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .ok_or_else(|| "learning event scope is missing".to_string())?;
    if !matches!(
        scope,
        "general"
            | "global"
            | "domain"
            | "project"
            | "component"
            | "temporary"
            | "device"
            | "vault"
    ) {
        return Err("learning event scope is invalid".to_string());
    }
    for key in ["event_id", "owner_vault_id", "device_id"] {
        let text = object
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("learning event {key} is missing"))?;
        if text.len() > 64 {
            return Err(format!("learning event {key} exceeds bound"));
        }
    }
    Ok(())
}

pub fn validate_legacy_learning_import(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "legacy learning import must be an object".to_string())?;
    if object.len() > 64 {
        return Err("legacy learning import has too many fields".to_string());
    }
    let encoded = serde_json::to_vec(value).map_err(|_| "legacy import cannot serialize")?;
    if encoded.len() > MAX_INPUT {
        return Err("legacy learning import exceeds bound".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_parser_and_envelope_reject_invalid_inputs() {
        assert!(parse_bounded_request(b"[]").is_err());
        let value = parse_bounded_request(br#"{"op":"verify","signature":"%%%"}"#).unwrap();
        assert!(validate_crypto_envelope(&value).is_err());
        let learning = parse_bounded_request(
            br#"{"payload_schema_version":3,"scope":"domain","event_id":"e","owner_vault_id":"o","device_id":"d"}"#,
        )
        .unwrap();
        assert!(validate_learning_event_v3(&learning).is_ok());
        assert!(validate_legacy_learning_import(&learning).is_ok());
    }
}
