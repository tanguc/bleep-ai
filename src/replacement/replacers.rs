/// generate a fake value for the given replacement_type.
///
/// `replacement_type` is the snake_case string matching the ReplacementType enum values.
/// `rule_id` is used for the unknown-type fallback label only.
/// `original` is the raw matched bytes — needed for length-preserving and value-aware fakers.
///
/// returns a JSON-safe string ready for splicing into the body.
pub fn generate(replacement_type: &str, rule_id: &str, original: &[u8]) -> String {
    match replacement_type {
        "faker_email" => fake_email(),
        "faker_phone" => fake_phone(),
        "faker_ssn" => fake_ssn(),
        "faker_cc_luhn" => fake_cc_luhn(),
        "faker_iban" => fake_iban(),
        "faker_uuid" => fake_uuid(),
        "faker_ipv4" => fake_ipv4(),
        "faker_aws_key" => fake_aws_key(),
        "faker_github_pat" => fake_github_pat(),
        "faker_jwt" => fake_jwt(),
        "faker_api_key" => fake_api_key(),
        "faker_db_conn" => fake_db_conn(std::str::from_utf8(original).unwrap_or("")),
        "faker_url_cred" => fake_url_cred(std::str::from_utf8(original).unwrap_or("")),
        "fpe_numeric" => fake_fpe_numeric(original),
        "generic_random" => fake_generic_random(original),
        "passthrough" => unreachable!(
            "passthrough is checked by apply() before calling generate"
        ),
        _ => format!("[REDACTED:{rule_id}]"),
    }
}

// --- simple fakers ---

fn fake_email() -> String {
    const NAMES: &[&str] = &[
        "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "henry",
        "iris", "jack", "kate", "leon", "mia", "noah", "olivia", "paul",
        "quinn", "rose", "sam", "tara", "uma", "victor", "wendy", "xena",
        "yara", "zoe", "andy", "beth", "carl", "diana",
    ];
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let word = NAMES[rng.gen_range(0..NAMES.len())];
    format!("{}@example.com", word)
}

fn fake_phone() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("+1-555-010-{:04}", rng.gen_range(0..10000u32))
}

fn fake_ssn() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("000-00-{:04}", rng.gen_range(0..10000u32))
}

fn fake_ipv4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("203.0.113.{}", rng.gen_range(0..256u32))
}

fn fake_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn fake_iban() -> String {
    "GB00BLEEP0000000000000".to_string()
}

fn fake_aws_key() -> String {
    use rand::Rng;
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..11)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    format!("AKIABLEEP{}", suffix)
}

fn fake_github_pat() -> String {
    use rand::Rng;
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..31)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    format!("ghp_BLEEP{}", suffix)
}

fn fake_api_key() -> String {
    use rand::Rng;
    let charset: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

// --- complex fakers ---

fn fake_cc_luhn() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // 15 digits: "400000" prefix + 9 random digits
    let mut digits = [0u8; 15];
    digits[0] = 4;
    digits[1] = 0;
    digits[2] = 0;
    digits[3] = 0;
    digits[4] = 0;
    digits[5] = 0;
    for d in digits[6..15].iter_mut() {
        *d = rng.gen_range(0..10);
    }

    let check = luhn_check_digit(&digits);
    let mut all = [0u8; 16];
    all[..15].copy_from_slice(&digits);
    all[15] = check;

    all.iter().map(|d| (b'0' + d) as char).collect()
}

fn luhn_check_digit(digits: &[u8]) -> u8 {
    let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
        if i % 2 == 0 {
            let v = d as u32 * 2;
            if v > 9 { v - 9 } else { v }
        } else {
            d as u32
        }
    }).sum();
    ((10 - (sum % 10)) % 10) as u8
}

fn fake_jwt() -> String {
    use base64::Engine;
    use rand::Rng;

    let header_json = br#"{"alg":"HS256","typ":"JWT","bleep":true}"#;
    let payload_json = br#"{"sub":"bleep-fake","iat":1000000000}"#;

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(header_json);
    let payload = engine.encode(payload_json);

    let b64_charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut rng = rand::thread_rng();
    let signature: String = (0..43)
        .map(|_| b64_charset[rng.gen_range(0..b64_charset.len())] as char)
        .collect();

    format!("{}.{}.{}", header, payload, signature)
}

fn fake_db_conn(original: &str) -> String {
    let fallback = "postgresql://bleep:bleep@bleep-fake-db.invalid:5432/dbname".to_string();
    match url::Url::parse(original) {
        Ok(mut u) => {
            // replace credentials and host
            let _ = u.set_host(Some("bleep-fake-db.invalid"));
            let _ = u.set_username("bleep");
            let _ = u.set_password(Some("bleep"));
            u.to_string()
        }
        Err(_) => fallback,
    }
}

fn fake_url_cred(original: &str) -> String {
    match url::Url::parse(original) {
        Ok(mut u) => {
            let _ = u.set_username("bleep");
            let _ = u.set_password(Some("bleep"));
            u.to_string()
        }
        Err(_) => original.to_string(),
    }
}

fn fake_fpe_numeric(original: &[u8]) -> String {
    // collect digit values from original
    let digits: Vec<u16> = original
        .iter()
        .filter(|&&b| b.is_ascii_digit())
        .map(|&b| (b - b'0') as u16)
        .collect();

    if digits.is_empty() {
        return "0".to_string();
    }

    // FF1 with radix=10 requires minlen >= 7 (10^7 >= 1_000_000)
    // for shorter digit strings, fall back to generic_random
    if digits.len() < 7 {
        return fake_generic_random(original);
    }

    // use the fpe crate with a fixed 32-byte zero key
    // key management is deferred to v1.1 — a static zero key is used as fallback
    let key = [0u8; 32];
    let ff1 = match fpe::ff1::FF1::<aes::Aes256>::new(&key, 10) {
        Ok(f) => f,
        Err(_) => return fake_generic_random(original),
    };
    let ns = fpe::ff1::FlexibleNumeralString::from(digits);
    match ff1.encrypt(&[], &ns) {
        Ok(encrypted) => {
            let out: Vec<u16> = encrypted.into();
            out.iter().map(|&d| (b'0' + d as u8) as char).collect()
        }
        Err(_) => fake_generic_random(original),
    }
}

pub fn fake_generic_random(original: &[u8]) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    if original.is_empty() {
        return String::new();
    }

    // detect charset from original bytes
    let all_hex = original.iter().all(|&b| b.is_ascii_hexdigit());
    let all_alpha = original.iter().all(|&b| b.is_ascii_alphabetic());
    let all_digit = original.iter().all(|&b| b.is_ascii_digit());
    let all_alnum = original.iter().all(|&b| b.is_ascii_alphanumeric());

    let charset: &[u8] = if all_digit {
        b"0123456789"
    } else if all_hex && !all_alpha {
        // hex but not purely alpha — use lowercase hex
        b"0123456789abcdef"
    } else if all_alpha {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    } else if all_alnum {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    };

    (0..original.len())
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_email_format() {
        let e = fake_email();
        assert!(e.ends_with("@example.com"), "email should end with @example.com, got: {}", e);
        let re = regex::Regex::new(r"^[a-z]+@example\.com$").unwrap();
        assert!(re.is_match(&e), "email format mismatch: {}", e);
    }

    #[test]
    fn test_fake_phone_format() {
        let p = fake_phone();
        let re = regex::Regex::new(r"^\+1-555-010-\d{4}$").unwrap();
        assert!(re.is_match(&p), "phone format mismatch: {}", p);
    }

    #[test]
    fn test_fake_ssn_format() {
        let s = fake_ssn();
        let re = regex::Regex::new(r"^000-00-\d{4}$").unwrap();
        assert!(re.is_match(&s), "ssn format mismatch: {}", s);
    }

    #[test]
    fn test_fake_ipv4_format() {
        let ip = fake_ipv4();
        let re = regex::Regex::new(r"^203\.0\.113\.\d{1,3}$").unwrap();
        assert!(re.is_match(&ip), "ipv4 format mismatch: {}", ip);
    }

    #[test]
    fn test_fake_uuid_format() {
        let u = fake_uuid();
        // UUID v4: 8-4-4-4-12
        let re = regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").unwrap();
        assert!(re.is_match(&u), "uuid format mismatch: {}", u);
    }

    #[test]
    fn test_fake_aws_key() {
        let k = fake_aws_key();
        assert_eq!(k.len(), 20, "aws key must be 20 chars, got {}", k.len());
        assert!(k.starts_with("AKIABLEEP"), "aws key must start with AKIABLEEP, got {}", k);
    }

    #[test]
    fn test_fake_github_pat() {
        let p = fake_github_pat();
        assert_eq!(p.len(), 40, "github pat must be 40 chars, got {}", p.len());
        assert!(p.starts_with("ghp_BLEEP"), "github pat must start with ghp_BLEEP, got {}", p);
    }

    #[test]
    fn test_fake_api_key() {
        let k = fake_api_key();
        assert_eq!(k.len(), 32, "api key must be 32 chars, got {}", k.len());
        let re = regex::Regex::new(r"^[0-9a-f]{32}$").unwrap();
        assert!(re.is_match(&k), "api key must be hex, got {}", k);
    }

    #[test]
    fn test_fake_cc_luhn_valid() {
        let cc = fake_cc_luhn();
        assert_eq!(cc.len(), 16, "cc must be 16 digits, got {}", cc.len());
        assert!(cc.starts_with("400000"), "cc must start with 400000, got {}", cc);

        // verify luhn validity
        let digits: Vec<u8> = cc.bytes().map(|b| b - b'0').collect();
        let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
            if i % 2 == 1 {
                let v = d as u32 * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d as u32
            }
        }).sum();
        assert_eq!(sum % 10, 0, "cc failed luhn check: {}", cc);
    }

    #[test]
    fn test_fake_jwt_segments() {
        let jwt = fake_jwt();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "jwt must have 3 segments, got: {}", jwt);

        // decode header and check bleep:true
        use base64::Engine;
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_str = String::from_utf8(header_bytes).unwrap();
        assert!(header_str.contains("bleep"), "jwt header must contain bleep marker: {}", header_str);
    }

    #[test]
    fn test_fake_db_conn_replaces_creds() {
        let result = fake_db_conn("postgresql://user:secret@db.example.com:5432/mydb");
        assert!(result.contains("bleep-fake-db.invalid"), "must use fake host: {}", result);
        assert!(result.contains("bleep:bleep@"), "must use bleep creds: {}", result);
    }

    #[test]
    fn test_fake_url_cred_replaces_only_creds() {
        let result = fake_url_cred("https://admin:secret@api.example.com/v1");
        assert!(result.contains("bleep:bleep@"), "must replace creds: {}", result);
        assert!(result.contains("api.example.com"), "must preserve host: {}", result);
    }

    #[test]
    fn test_generic_random_same_length() {
        let orig = b"ABCDEF12";
        let result = fake_generic_random(orig);
        assert_eq!(result.len(), orig.len(), "generic_random must preserve length");
    }

    #[test]
    fn test_generic_random_digit_only() {
        let orig = b"123456";
        let result = fake_generic_random(orig);
        assert_eq!(result.len(), 6);
        assert!(result.bytes().all(|b| b.is_ascii_digit()), "all-digit input should produce digits: {}", result);
    }

    #[test]
    fn test_fpe_numeric_same_length() {
        let orig = b"123456789";
        let result = fake_fpe_numeric(orig);
        assert_eq!(result.len(), orig.len(), "fpe_numeric must preserve digit count");
        assert!(result.bytes().all(|b| b.is_ascii_digit()), "fpe output must be digits: {}", result);
    }

    #[test]
    fn test_json_safety_all_types() {
        let types = [
            ("faker_email", b"old@real.com" as &[u8]),
            ("faker_phone", b"+1-212-555-0100"),
            ("faker_ssn", b"123-45-6789"),
            ("faker_cc_luhn", b"4532015112830366"),
            ("faker_iban", b"GB82WEST12345698765432"),
            ("faker_uuid", b"550e8400-e29b-41d4-a716-446655440000"),
            ("faker_ipv4", b"192.168.1.1"),
            ("faker_aws_key", b"AKIAIOSFODNN7EXAMPLE"),
            ("faker_github_pat", b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"),
            ("faker_jwt", b"eyJ0.eyJ1.sig"),
            ("faker_api_key", b"abc123def456abc123def456abc123de"),
            ("faker_db_conn", b"postgresql://user:pass@host:5432/db"),
            ("faker_url_cred", b"https://admin:pass@api.example.com/v1"),
            ("fpe_numeric", b"123456789"),
            ("generic_random", b"ABCDEF1234"),
        ];
        for (rt, original) in &types {
            let fake = generate(rt, "test-rule", original);
            let json_str = format!("\"{}\"", fake);
            serde_json::from_str::<serde_json::Value>(&json_str)
                .unwrap_or_else(|e| panic!("{} produced non-JSON-safe value {:?}: {}", rt, fake, e));
        }
    }
}
