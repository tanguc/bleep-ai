//! Fake-value generators for redaction.
//!
//! By default every replacer mimics the input — same length, same format, same
//! charset class — so the fake is indistinguishable from the original to a
//! reader that doesn't have the side-channel forward map. Set
//! `BLEEP_VISIBLE_MARKERS=1` (or `=true`) to switch to legacy "audit-friendly"
//! markers (`AKIABLEEP...`, `bleep:bleep@`, etc.) for dev / log review.
//!
//! Tests should call the explicit `*_realistic` / `*_visible` helpers directly
//! to avoid races on the process-wide env var.

use rand::Rng;
use std::sync::OnceLock;

/// generate a fake value for the given replacement_type.
///
/// `replacement_type` is the snake_case string matching the ReplacementType enum values.
/// `rule_id` is used for the unknown-type fallback label only.
/// `original` is the raw matched bytes — needed for length-preserving and value-aware fakers.
///
/// returns a JSON-safe string ready for splicing into the body.
pub fn generate(
    replacement_type: &str,
    rule_id: &str,
    original: &[u8],
    literal_prefix: Option<&str>,
) -> String {
    match replacement_type {
        "faker_email" => fake_email(original),
        "faker_phone" => fake_phone(original),
        "faker_ssn" => fake_ssn(original),
        "faker_cc_luhn" => fake_cc_luhn(original),
        "faker_iban" => fake_iban(original),
        "faker_uuid" => fake_uuid(),
        "faker_ipv4" => fake_ipv4(original),
        "faker_aws_key" => fake_aws_key(original),
        "faker_github_pat" => fake_github_pat(original),
        "faker_jwt" => fake_jwt(original),
        "faker_api_key" => with_literal_prefix(original, literal_prefix, fake_api_key),
        "faker_db_conn" => fake_db_conn(std::str::from_utf8(original).unwrap_or("")),
        "faker_url_cred" => fake_url_cred(std::str::from_utf8(original).unwrap_or("")),
        "fpe_numeric" => fake_fpe_numeric(original),
        "generic_random" => with_literal_prefix(original, literal_prefix, fake_generic_random),
        "passthrough" => unreachable!("passthrough is checked by apply() before calling generate"),
        _ => format!("[REDACTED:{rule_id}]"),
    }
}

/// Wrap a realistic fake generator so the rule's literal prefix (e.g. `hf_`,
/// `AKIA`) is preserved verbatim in the output. Only kicks in when:
///   - `literal_prefix` is provided (set by build-rules from the regex)
///   - `original` actually starts with that prefix (sanity check — the regex
///     matched, so this should almost always be true)
///   - we have at least one byte beyond the prefix to randomize
///   - visible-marker mode is OFF (visible mode is intentionally non-realistic)
///
/// Without this wrap, `fake_api_key_realistic` re-rolls every alphanumeric in
/// the input — which silently destroys the vendor prefix and produces a fake
/// that no longer matches the rule's regex, breaking downstream re-detection
/// and undermining the realistic-mimicry design.
fn with_literal_prefix<F: Fn(&[u8]) -> String>(
    original: &[u8],
    literal_prefix: Option<&str>,
    f: F,
) -> String {
    if !markers_visible() {
        if let Some(p) = literal_prefix {
            let pb = p.as_bytes();
            if !pb.is_empty() && original.len() > pb.len() && original.starts_with(pb) {
                let rest_fake = f(&original[pb.len()..]);
                let mut s = String::with_capacity(pb.len() + rest_fake.len());
                s.push_str(p);
                s.push_str(&rest_fake);
                return s;
            }
        }
    }
    f(original)
}

// ── env var toggle ─────────────────────────────────────────────────────────────

/// returns true if `BLEEP_VISIBLE_MARKERS` env var is set to `1` or `true`.
/// Cached on first call — env changes after first read are ignored.
pub fn markers_visible() -> bool {
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("BLEEP_VISIBLE_MARKERS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

// ── small helpers ──────────────────────────────────────────────────────────────

fn random_alphalower(n: usize) -> String {
    let mut rng = rand::thread_rng();
    let cs = b"abcdefghijklmnopqrstuvwxyz";
    (0..n)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect()
}

fn random_alnum(n: usize) -> String {
    let mut rng = rand::thread_rng();
    let cs = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect()
}

fn random_alnum_upper(n: usize) -> String {
    let mut rng = rand::thread_rng();
    let cs = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..n)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect()
}

fn random_b62(n: usize) -> String {
    let mut rng = rand::thread_rng();
    let cs = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect()
}

// ── email ──────────────────────────────────────────────────────────────────────

pub(crate) fn fake_email(original: &[u8]) -> String {
    if markers_visible() {
        fake_email_visible()
    } else {
        fake_email_realistic(original)
    }
}

pub(crate) fn fake_email_visible() -> String {
    const NAMES: &[&str] = &[
        "alice", "bob", "charlie", "dave", "eve", "frank", "grace", "henry", "iris", "jack",
        "kate", "leon", "mia", "noah", "olivia", "paul", "quinn", "rose", "sam", "tara", "uma",
        "victor", "wendy", "xena", "yara", "zoe", "andy", "beth", "carl", "diana",
    ];
    let mut rng = rand::thread_rng();
    let word = NAMES[rng.gen_range(0..NAMES.len())];
    format!("{}@example.com", word)
}

pub(crate) fn fake_email_realistic(original: &[u8]) -> String {
    let s = std::str::from_utf8(original).unwrap_or("");
    // try to mimic input handle length, clamped to a plausible range
    let handle_len = s
        .split('@')
        .next()
        .map(|h| h.len())
        .unwrap_or(8)
        .clamp(5, 24);
    let mut rng = rand::thread_rng();
    let domains = ["example.com", "example.org", "example.net"];
    let domain = domains[rng.gen_range(0..domains.len())];
    format!("{}@{}", random_alnum(handle_len), domain)
}

// ── phone ──────────────────────────────────────────────────────────────────────

pub(crate) fn fake_phone(original: &[u8]) -> String {
    if markers_visible() {
        fake_phone_visible()
    } else {
        fake_phone_realistic(original)
    }
}

pub(crate) fn fake_phone_visible() -> String {
    let mut rng = rand::thread_rng();
    format!("+1-555-010-{:04}", rng.gen_range(0..10000u32))
}

pub(crate) fn fake_phone_realistic(original: &[u8]) -> String {
    let s = std::str::from_utf8(original).unwrap_or("");
    if s.is_empty() {
        return "+1-555-010-0000".to_string();
    }
    let mut rng = rand::thread_rng();
    s.chars()
        .map(|c| {
            if c.is_ascii_digit() {
                char::from_digit(rng.gen_range(0..10), 10).unwrap()
            } else {
                c
            }
        })
        .collect()
}

// ── ssn ────────────────────────────────────────────────────────────────────────

pub(crate) fn fake_ssn(original: &[u8]) -> String {
    if markers_visible() {
        fake_ssn_visible()
    } else {
        fake_ssn_realistic(original)
    }
}

pub(crate) fn fake_ssn_visible() -> String {
    let mut rng = rand::thread_rng();
    format!("000-00-{:04}", rng.gen_range(0..10000u32))
}

pub(crate) fn fake_ssn_realistic(_original: &[u8]) -> String {
    // 9XX area codes are unallocated by SSA. Avoid 9XX-7X / 9XX-8X (ITIN range).
    let mut rng = rand::thread_rng();
    let area = rng.gen_range(900..1000);
    let group = rng.gen_range(1..66);
    let serial = rng.gen_range(1..10000);
    format!("{:03}-{:02}-{:04}", area, group, serial)
}

// ── ipv4 ───────────────────────────────────────────────────────────────────────

pub(crate) fn fake_ipv4(original: &[u8]) -> String {
    if markers_visible() {
        fake_ipv4_visible()
    } else {
        fake_ipv4_realistic(original)
    }
}

pub(crate) fn fake_ipv4_visible() -> String {
    let mut rng = rand::thread_rng();
    format!("203.0.113.{}", rng.gen_range(0..256u32))
}

pub(crate) fn fake_ipv4_realistic(_original: &[u8]) -> String {
    // rotate among the three RFC 5737 TEST-NET ranges to reduce predictability
    let mut rng = rand::thread_rng();
    let bases = [(192, 0, 2), (198, 51, 100), (203, 0, 113)];
    let (a, b, c) = bases[rng.gen_range(0..3)];
    let d = rng.gen_range(1..255);
    format!("{}.{}.{}.{}", a, b, c, d)
}

// ── uuid ───────────────────────────────────────────────────────────────────────

pub(crate) fn fake_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ── iban ───────────────────────────────────────────────────────────────────────

pub(crate) fn fake_iban(original: &[u8]) -> String {
    if markers_visible() {
        fake_iban_visible()
    } else {
        fake_iban_realistic(original)
    }
}

pub(crate) fn fake_iban_visible() -> String {
    "GB00BLEEP0000000000000".to_string()
}

pub(crate) fn fake_iban_realistic(original: &[u8]) -> String {
    let s = std::str::from_utf8(original).unwrap_or("");

    // detect country from first two uppercase letters, default GB
    let country: String = if s.len() >= 2
        && s.as_bytes()[0].is_ascii_uppercase()
        && s.as_bytes()[1].is_ascii_uppercase()
    {
        s[0..2].to_string()
    } else {
        "GB".to_string()
    };

    // approximate IBAN lengths (most G7 countries) — fall back to input length when present
    let target_len = match country.as_str() {
        "AL" => 28,
        "AD" => 24,
        "AT" => 20,
        "AZ" => 28,
        "BH" => 22,
        "BE" => 16,
        "BA" => 20,
        "BR" => 29,
        "BG" => 22,
        "CR" => 22,
        "HR" => 21,
        "CY" => 28,
        "CZ" => 24,
        "DK" => 18,
        "DO" => 28,
        "EE" => 20,
        "FO" => 18,
        "FI" => 18,
        "FR" => 27,
        "GE" => 22,
        "DE" => 22,
        "GI" => 23,
        "GR" => 27,
        "GL" => 18,
        "GT" => 28,
        "HU" => 28,
        "IS" => 26,
        "IE" => 22,
        "IL" => 23,
        "IT" => 27,
        "JO" => 30,
        "KZ" => 20,
        "KW" => 30,
        "LV" => 21,
        "LB" => 28,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "MK" => 19,
        "MT" => 31,
        "MR" => 27,
        "MU" => 30,
        "MD" => 24,
        "MC" => 27,
        "ME" => 22,
        "NL" => 18,
        "NO" => 15,
        "PK" => 24,
        "PS" => 29,
        "PL" => 28,
        "PT" => 25,
        "QA" => 29,
        "RO" => 24,
        "SM" => 27,
        "SA" => 24,
        "RS" => 22,
        "SK" => 24,
        "SI" => 19,
        "ES" => 24,
        "SE" => 24,
        "CH" => 21,
        "TN" => 24,
        "TR" => 26,
        "AE" => 23,
        "GB" => 22,
        "VG" => 24,
        _ => s.len().clamp(15, 34),
    };

    let bban_len = target_len.saturating_sub(4);
    let bban = random_alnum_upper(bban_len);
    let check = iban_check_digits(&country, &bban);
    format!("{}{:02}{}", country, check, bban)
}

fn iban_check_digits(country: &str, bban: &str) -> u8 {
    // mod-97 over (BBAN + country + "00") with letters mapped A=10 .. Z=35
    let mut num_str = String::new();
    for c in bban.chars() {
        if let Some(d) = c.to_digit(10) {
            num_str.push_str(&d.to_string());
        } else if c.is_ascii_alphabetic() {
            let v = (c.to_ascii_uppercase() as u8 - b'A' + 10) as u32;
            num_str.push_str(&v.to_string());
        }
    }
    for c in country.chars() {
        let v = (c.to_ascii_uppercase() as u8 - b'A' + 10) as u32;
        num_str.push_str(&v.to_string());
    }
    num_str.push_str("00");
    let mut rem: u32 = 0;
    for byte in num_str.bytes() {
        rem = (rem * 10 + (byte - b'0') as u32) % 97;
    }
    (98 - rem) as u8
}

// ── aws access key id ─────────────────────────────────────────────────────────

pub(crate) fn fake_aws_key(original: &[u8]) -> String {
    if markers_visible() {
        fake_aws_key_visible()
    } else {
        fake_aws_key_realistic(original)
    }
}

pub(crate) fn fake_aws_key_visible() -> String {
    let mut rng = rand::thread_rng();
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let suffix: String = (0..11)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    format!("AKIABLEEP{}", suffix)
}

pub(crate) fn fake_aws_key_realistic(original: &[u8]) -> String {
    // detect prefix (AKIA / ASIA / AROA / etc.), preserve it, fill rest with alnum-upper
    let prefix = detect_aws_prefix(original).unwrap_or("AKIA");
    let suffix_len = 20usize.saturating_sub(prefix.len());
    format!("{}{}", prefix, random_alnum_upper(suffix_len))
}

fn detect_aws_prefix(original: &[u8]) -> Option<&'static str> {
    let s = std::str::from_utf8(original).ok()?;
    // 4-char prefixes (AWS access key id)
    for p in &[
        "AKIA", "ASIA", "AROA", "AGPA", "AIDA", "AIPA", "ANPA", "ANVA",
    ] {
        if s.starts_with(*p) {
            return Some(*p);
        }
    }
    if s.starts_with("A3T") {
        return Some("A3T");
    }
    None
}

// ── github pat ─────────────────────────────────────────────────────────────────

pub(crate) fn fake_github_pat(original: &[u8]) -> String {
    if markers_visible() {
        fake_github_pat_visible()
    } else {
        fake_github_pat_realistic(original)
    }
}

pub(crate) fn fake_github_pat_visible() -> String {
    let mut rng = rand::thread_rng();
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let suffix: String = (0..31)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    format!("ghp_BLEEP{}", suffix)
}

pub(crate) fn fake_github_pat_realistic(original: &[u8]) -> String {
    let s = std::str::from_utf8(original).unwrap_or("");
    if s.starts_with("github_pat_") {
        // fine-grained PAT: github_pat_<22>_<82> → 116 total
        format!("github_pat_{}_{}", random_b62(22), random_b62(82))
    } else {
        let prefix = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
            .iter()
            .find(|p| s.starts_with(**p))
            .copied()
            .unwrap_or("ghp_");
        format!("{}{}", prefix, random_b62(36))
    }
}

// ── jwt ────────────────────────────────────────────────────────────────────────

pub(crate) fn fake_jwt(original: &[u8]) -> String {
    if markers_visible() {
        fake_jwt_visible()
    } else {
        fake_jwt_realistic(original)
    }
}

pub(crate) fn fake_jwt_visible() -> String {
    use base64::Engine;
    let header_json = br#"{"alg":"HS256","typ":"JWT","bleep":true}"#;
    let payload_json = br#"{"sub":"bleep-fake","iat":1000000000}"#;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(header_json);
    let payload = engine.encode(payload_json);
    let mut rng = rand::thread_rng();
    let cs: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let signature: String = (0..43)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect();
    format!("{}.{}.{}", header, payload, signature)
}

pub(crate) fn fake_jwt_realistic(_original: &[u8]) -> String {
    use base64::Engine;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000);
    let header_json = br#"{"alg":"HS256","typ":"JWT"}"#;
    let payload_json = format!(
        r#"{{"sub":"{}","iat":{},"exp":{}}}"#,
        uuid::Uuid::new_v4(),
        now,
        now + 3600
    );
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(header_json);
    let payload = engine.encode(payload_json.as_bytes());
    let mut rng = rand::thread_rng();
    let cs: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let signature: String = (0..43)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect();
    format!("{}.{}.{}", header, payload, signature)
}

// ── api key (catch-all for typed-but-shapeless secrets) ───────────────────────

pub(crate) fn fake_api_key(original: &[u8]) -> String {
    if markers_visible() {
        fake_api_key_visible()
    } else {
        fake_api_key_realistic(original)
    }
}

pub(crate) fn fake_api_key_visible() -> String {
    let mut rng = rand::thread_rng();
    let cs: &[u8] = b"0123456789abcdef";
    (0..32)
        .map(|_| cs[rng.gen_range(0..cs.len())] as char)
        .collect()
}

pub(crate) fn fake_api_key_realistic(original: &[u8]) -> String {
    if original.is_empty() {
        return random_alnum(32);
    }
    // preserve non-alnum separators in their positions, randomize alnum chars
    // using a charset that matches the dominant case-class of the input
    let alpha_bytes: Vec<u8> = original
        .iter()
        .copied()
        .filter(|b| b.is_ascii_alphabetic())
        .collect();
    let alnum_bytes: Vec<u8> = original
        .iter()
        .copied()
        .filter(|b| b.is_ascii_alphanumeric())
        .collect();

    let all_lower = !alpha_bytes.is_empty() && alpha_bytes.iter().all(|b| b.is_ascii_lowercase());
    let all_upper = !alpha_bytes.is_empty() && alpha_bytes.iter().all(|b| b.is_ascii_uppercase());
    let all_hex = !alnum_bytes.is_empty() && alnum_bytes.iter().all(|b| b.is_ascii_hexdigit());

    let body_charset: &[u8] = if all_hex {
        b"0123456789abcdef"
    } else if all_lower {
        b"abcdefghijklmnopqrstuvwxyz0123456789"
    } else if all_upper {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    };

    let mut rng = rand::thread_rng();
    original
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() {
                body_charset[rng.gen_range(0..body_charset.len())] as char
            } else {
                b as char
            }
        })
        .collect()
}

// ── credit card (luhn) ─────────────────────────────────────────────────────────

pub(crate) fn fake_cc_luhn(original: &[u8]) -> String {
    if markers_visible() {
        fake_cc_luhn_visible()
    } else {
        fake_cc_luhn_realistic(original)
    }
}

pub(crate) fn fake_cc_luhn_visible() -> String {
    let mut rng = rand::thread_rng();
    let mut digits = [0u8; 15];
    digits[0] = 4;
    for d in digits[6..15].iter_mut() {
        *d = rng.gen_range(0..10);
    }
    let check = luhn_check_digit(&digits);
    let mut all = [0u8; 16];
    all[..15].copy_from_slice(&digits);
    all[15] = check;
    all.iter().map(|d| (b'0' + d) as char).collect()
}

pub(crate) fn fake_cc_luhn_realistic(original: &[u8]) -> String {
    // preserve length (clamped 13..=19) and BIN (first 4 digits) from input
    let in_digits: Vec<u8> = original
        .iter()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    let len = in_digits.len().clamp(13, 19);
    let mut new_digits = vec![0u8; len];

    let bin_keep = in_digits.len().min(4).min(len.saturating_sub(1));
    for i in 0..bin_keep {
        new_digits[i] = in_digits[i];
    }
    if bin_keep == 0 {
        new_digits[0] = 4; // visa default
    }
    let body_start = bin_keep.max(1);
    let mut rng = rand::thread_rng();
    for d in new_digits[body_start..len - 1].iter_mut() {
        *d = rng.gen_range(0..10);
    }
    new_digits[len - 1] = luhn_check_digit(&new_digits[..len - 1]);
    new_digits.iter().map(|d| (b'0' + d) as char).collect()
}

fn luhn_check_digit(digits: &[u8]) -> u8 {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 0 {
                let v = d as u32 * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d as u32
            }
        })
        .sum();
    ((10 - (sum % 10)) % 10) as u8
}

// ── url cred replacer ─────────────────────────────────────────────────────────

pub(crate) fn fake_url_cred(original: &str) -> String {
    if markers_visible() {
        fake_url_cred_visible(original)
    } else {
        fake_url_cred_realistic(original)
    }
}

pub(crate) fn fake_url_cred_visible(original: &str) -> String {
    match url::Url::parse(original) {
        Ok(mut u) => {
            let _ = u.set_username("bleep");
            let _ = u.set_password(Some("bleep"));
            u.to_string()
        }
        Err(_) => original.to_string(),
    }
}

pub(crate) fn fake_url_cred_realistic(original: &str) -> String {
    match url::Url::parse(original) {
        Ok(mut u) => {
            let _ = u.set_username(&random_alphalower(8));
            let _ = u.set_password(Some(&random_alnum(20)));
            u.to_string()
        }
        Err(_) => fake_generic_random(original.as_bytes()),
    }
}

// ── db conn ────────────────────────────────────────────────────────────────────

pub(crate) fn fake_db_conn(original: &str) -> String {
    if markers_visible() {
        fake_db_conn_visible()
    } else {
        fake_db_conn_realistic(original)
    }
}

pub(crate) fn fake_db_conn_visible() -> String {
    "postgresql://bleep:bleep@bleep-fake-db.invalid:5432/dbname".to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DbConnFormat {
    Url,       // scheme://user:pass@host[:port]/db
    Jdbc,      // jdbc:dialect://...
    AdoNet,    // Server=...;Database=...;User Id=...;Password=...;
    Odbc,      // Driver={...};Server=...;...
    LibpqKv,   // host=... port=... user=... password=... dbname=...
    OracleTns, // (DESCRIPTION=(ADDRESS=...)(CONNECT_DATA=...))
    Unknown,
}

pub(crate) fn classify_db_conn(s: &str) -> DbConnFormat {
    let trimmed = s.trim();
    if trimmed.starts_with("jdbc:") {
        return DbConnFormat::Jdbc;
    }
    if trimmed.starts_with('(') && trimmed.to_uppercase().contains("DESCRIPTION") {
        return DbConnFormat::OracleTns;
    }
    if trimmed.contains("://") {
        return DbConnFormat::Url;
    }
    let has_semi = trimmed.contains(';');
    let has_eq = trimmed.contains('=');
    if has_semi && has_eq {
        let lower = trimmed.to_lowercase();
        if lower.contains("driver=") || lower.contains("driver={") {
            return DbConnFormat::Odbc;
        }
        return DbConnFormat::AdoNet;
    }
    if has_eq
        && trimmed
            .split_whitespace()
            .filter(|w| w.contains('='))
            .count()
            >= 2
    {
        return DbConnFormat::LibpqKv;
    }
    DbConnFormat::Unknown
}

pub(crate) fn fake_db_conn_realistic(original: &str) -> String {
    match classify_db_conn(original) {
        DbConnFormat::Url => fake_db_url(original),
        DbConnFormat::Jdbc => fake_db_jdbc(original),
        DbConnFormat::AdoNet => fake_db_adonet(original),
        DbConnFormat::Odbc => fake_db_adonet(original), // same KV grammar
        DbConnFormat::LibpqKv => fake_db_libpq(original),
        DbConnFormat::OracleTns => fake_db_oracle(original),
        DbConnFormat::Unknown => fake_generic_random(original.as_bytes()),
    }
}

fn fake_db_url(original: &str) -> String {
    match url::Url::parse(original) {
        Ok(mut u) => {
            let _ = u.set_username(&random_alphalower(8));
            let _ = u.set_password(Some(&random_alnum(20)));
            let _ = u.set_host(Some(&format!("{}.example.com", random_alphalower(10))));
            scrub_url_query_secrets(&mut u);
            u.to_string()
        }
        Err(_) => format!(
            "postgresql://{}:{}@{}.example.com:5432/{}",
            random_alphalower(8),
            random_alnum(20),
            random_alphalower(10),
            random_alphalower(8),
        ),
    }
}

fn scrub_url_query_secrets(u: &mut url::Url) {
    let pairs: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| {
            let key = k.into_owned();
            let lower = key.to_lowercase();
            let new_v = match lower.as_str() {
                "password" | "pwd" | "pass" => random_alnum(20),
                "user" | "username" | "uid" => random_alphalower(8),
                _ => v.into_owned(),
            };
            (key, new_v)
        })
        .collect();
    if !pairs.is_empty() {
        u.set_query(None);
        let mut q = u.query_pairs_mut();
        for (k, v) in &pairs {
            q.append_pair(k, v);
        }
    }
}

fn fake_db_jdbc(original: &str) -> String {
    let rest = original.trim_start_matches("jdbc:");
    if rest.contains("://") {
        // jdbc:postgresql://... — parse the inner URL
        let inner = fake_db_url(rest);
        format!("jdbc:{}", inner)
    } else if rest.contains(';') && rest.contains('=') {
        // jdbc:sqlserver://host;property=value (mixed shape)
        format!("jdbc:{}", fake_db_adonet(rest))
    } else {
        // jdbc:oracle:thin:@host:port:sid — opaque, fall back to charset-preserving random
        format!("jdbc:{}", fake_generic_random(rest.as_bytes()))
    }
}

fn fake_db_adonet(original: &str) -> String {
    // ; separated key=value pairs, case-insensitive keys
    let parts: Vec<String> = original
        .split(';')
        .map(|kv| {
            let trimmed = kv.trim();
            if trimmed.is_empty() {
                return String::new();
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let kl = k.trim().to_lowercase();
                let v_trimmed = v.trim();
                let new_v = match kl.as_str() {
                    "password" | "pwd" | "pass" => random_alnum(v_trimmed.len().max(12)),
                    "user id" | "uid" | "user" | "username" | "userid" => {
                        random_alphalower(v_trimmed.len().max(6))
                    }
                    "server" | "host" | "data source" | "address" | "addr" | "network address"
                    | "server name" => {
                        format!("{}.example.com", random_alphalower(10))
                    }
                    "database" | "initial catalog" => random_alphalower(v_trimmed.len().max(6)),
                    _ => v_trimmed.to_string(),
                };
                format!("{}={}", k.trim(), new_v)
            } else {
                trimmed.to_string()
            }
        })
        .filter(|s| !s.is_empty())
        .collect();
    let joined = parts.join(";");
    if original.trim_end().ends_with(';') {
        format!("{};", joined)
    } else {
        joined
    }
}

fn fake_db_libpq(original: &str) -> String {
    let parts: Vec<String> = original
        .split_whitespace()
        .map(|kv| {
            if let Some((k, v)) = kv.split_once('=') {
                let kl = k.to_lowercase();
                let new_v = match kl.as_str() {
                    "password" | "passfile" => random_alnum(v.len().max(12)),
                    "host" | "hostaddr" => format!("{}.example.com", random_alphalower(10)),
                    "user" => random_alphalower(v.len().max(6)),
                    "dbname" => random_alphalower(v.len().max(6)),
                    _ => v.to_string(),
                };
                format!("{}={}", k, new_v)
            } else {
                kv.to_string()
            }
        })
        .collect();
    parts.join(" ")
}

fn fake_db_oracle(original: &str) -> String {
    // replace HOST=, USER_ID=, USER=, PASSWORD= values inside a paren tree
    let re_host = regex::Regex::new(r"(?i)(HOST\s*=\s*)([^)]+)").unwrap();
    let re_user = regex::Regex::new(r"(?i)(USER(?:_ID|NAME)?\s*=\s*)([^)]+)").unwrap();
    let re_pass = regex::Regex::new(r"(?i)(PASSWORD\s*=\s*)([^)]+)").unwrap();
    let s = re_host.replace_all(original, |c: &regex::Captures| {
        format!("{}{}.example.com", &c[1], random_alphalower(10))
    });
    let s = re_user.replace_all(&s, |c: &regex::Captures| {
        format!("{}{}", &c[1], random_alphalower(8))
    });
    let s = re_pass.replace_all(&s, |c: &regex::Captures| {
        format!("{}{}", &c[1], random_alnum(16))
    });
    s.into_owned()
}

// ── fpe_numeric ────────────────────────────────────────────────────────────────

pub fn fake_fpe_numeric(original: &[u8]) -> String {
    let digits: Vec<u16> = original
        .iter()
        .filter(|&&b| b.is_ascii_digit())
        .map(|&b| (b - b'0') as u16)
        .collect();

    if digits.is_empty() {
        return "0".to_string();
    }
    if digits.len() < 7 {
        return fake_generic_random(original);
    }

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

// ── generic random (fallback for unknown shapes) ──────────────────────────────

pub fn fake_generic_random(original: &[u8]) -> String {
    let mut rng = rand::thread_rng();
    if original.is_empty() {
        return String::new();
    }
    let all_hex = original.iter().all(|&b| b.is_ascii_hexdigit());
    let all_alpha = original.iter().all(|&b| b.is_ascii_alphabetic());
    let all_digit = original.iter().all(|&b| b.is_ascii_digit());
    let all_alnum = original.iter().all(|&b| b.is_ascii_alphanumeric());

    let charset: &[u8] = if all_digit {
        b"0123456789"
    } else if all_hex && !all_alpha {
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

    // ── visible-mode legacy invariants (call _visible explicitly to bypass env) ─

    #[test]
    fn test_visible_aws_key_has_marker() {
        let k = fake_aws_key_visible();
        assert_eq!(k.len(), 20);
        assert!(k.starts_with("AKIABLEEP"), "got {}", k);
    }

    #[test]
    fn test_visible_github_pat_has_marker() {
        let p = fake_github_pat_visible();
        assert_eq!(p.len(), 40);
        assert!(p.starts_with("ghp_BLEEP"), "got {}", p);
    }

    #[test]
    fn test_visible_jwt_header_contains_bleep() {
        use base64::Engine;
        let jwt = fake_jwt_visible();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header_str = String::from_utf8(header_bytes).unwrap();
        assert!(header_str.contains("bleep"), "got {}", header_str);
    }

    #[test]
    fn test_visible_db_conn_has_marker() {
        let r = fake_db_conn_visible();
        assert!(r.contains("bleep:bleep@"), "got {}", r);
        assert!(r.contains("bleep-fake-db.invalid"), "got {}", r);
    }

    #[test]
    fn test_visible_url_cred_has_marker() {
        let r = fake_url_cred_visible("https://admin:secret@api.example.com/v1");
        assert!(r.contains("bleep:bleep@"), "got {}", r);
    }

    #[test]
    fn test_visible_iban_is_fixed() {
        assert_eq!(fake_iban_visible(), "GB00BLEEP0000000000000");
    }

    // ── realistic-mode invariants ────────────────────────────────────────────

    #[test]
    fn test_realistic_email_format_no_bleep() {
        let e = fake_email_realistic(b"someone@real-corp.com");
        let re =
            regex::Regex::new(r"^[a-z0-9]+@(example\.com|example\.org|example\.net)$").unwrap();
        assert!(re.is_match(&e), "got {}", e);
        assert!(!e.to_lowercase().contains("bleep"));
    }

    #[test]
    fn test_realistic_phone_preserves_format() {
        let p = fake_phone_realistic(b"+33 6 12 34 56 78");
        assert_eq!(p.len(), "+33 6 12 34 56 78".len());
        // separators preserved at same positions
        let orig = "+33 6 12 34 56 78";
        for (i, (a, b)) in orig.chars().zip(p.chars()).enumerate() {
            if !a.is_ascii_digit() {
                assert_eq!(
                    a, b,
                    "non-digit char must be preserved at pos {}: orig={} got={}",
                    i, a, b
                );
            }
        }
    }

    #[test]
    fn test_realistic_ssn_format() {
        let s = fake_ssn_realistic(b"123-45-6789");
        let re = regex::Regex::new(r"^9\d{2}-\d{2}-\d{4}$").unwrap();
        assert!(re.is_match(&s), "got {}", s);
    }

    #[test]
    fn test_realistic_ipv4_in_test_net() {
        for _ in 0..30 {
            let ip = fake_ipv4_realistic(b"8.8.8.8");
            let re = regex::Regex::new(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$").unwrap();
            assert!(re.is_match(&ip), "got {}", ip);
        }
    }

    #[test]
    fn test_realistic_aws_key_preserves_prefix() {
        let cases: &[(&[u8], &str)] = &[
            (b"AKIAIOSFODNN7EXAMPLE", "AKIA"),
            (b"ASIAEXAMPLEKEYIDHERE", "ASIA"),
            (b"AROAEXAMPLEKEYIDHERE", "AROA"),
        ];
        for (input, expected_prefix) in cases {
            let k = fake_aws_key_realistic(input);
            assert_eq!(k.len(), 20, "got {}", k);
            assert!(
                k.starts_with(expected_prefix),
                "expected prefix {} in {}",
                expected_prefix,
                k
            );
            assert!(!k.contains("BLEEP"));
            assert!(
                k.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            );
        }
    }

    #[test]
    fn test_realistic_github_pat_preserves_prefix() {
        let cases: &[(&[u8], &str, usize)] = &[
            (b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ghp_", 40),
            (b"gho_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gho_", 40),
            (b"github_pat_11AAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github_pat_", 116),
        ];
        for (input, expected_prefix, expected_len) in cases {
            let p = fake_github_pat_realistic(input);
            assert_eq!(
                p.len(),
                *expected_len,
                "len mismatch for {}: {}",
                expected_prefix,
                p
            );
            assert!(p.starts_with(expected_prefix), "got {}", p);
            assert!(!p.contains("BLEEP"));
        }
    }

    #[test]
    fn test_realistic_jwt_no_bleep() {
        use base64::Engine;
        let jwt = fake_jwt_realistic(b"old.jwt.value");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header_str = String::from_utf8(header_bytes).unwrap();
        assert!(
            !header_str.to_lowercase().contains("bleep"),
            "header leaked marker: {}",
            header_str
        );
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload_str = String::from_utf8(payload_bytes).unwrap();
        assert!(
            !payload_str.to_lowercase().contains("bleep"),
            "payload leaked marker: {}",
            payload_str
        );
    }

    #[test]
    fn test_realistic_iban_passes_mod97() {
        for cc in &["GB", "DE", "FR", "ES", "NL"] {
            let input = format!("{}00000000000000000000", cc);
            let iban = fake_iban_realistic(input.as_bytes());
            assert!(iban.starts_with(cc), "got {}", iban);
            assert!(verify_iban_mod97(&iban), "iban failed mod-97: {}", iban);
            assert!(!iban.to_uppercase().contains("BLEEP"));
        }
    }

    fn verify_iban_mod97(iban: &str) -> bool {
        // move first 4 chars to end, expand letters, mod 97 should be 1
        if iban.len() < 5 {
            return false;
        }
        let rearranged: String = iban[4..].chars().chain(iban[..4].chars()).collect();
        let mut num = String::new();
        for c in rearranged.chars() {
            if c.is_ascii_digit() {
                num.push(c);
            } else if c.is_ascii_alphabetic() {
                let v = (c.to_ascii_uppercase() as u8 - b'A' + 10) as u32;
                num.push_str(&v.to_string());
            } else {
                return false;
            }
        }
        let mut rem: u32 = 0;
        for byte in num.bytes() {
            rem = (rem * 10 + (byte - b'0') as u32) % 97;
        }
        rem == 1
    }

    #[test]
    fn test_realistic_cc_luhn_preserves_length_and_bin() {
        let cases: &[(&[u8], usize, &[u8])] = &[
            (b"4532015112830366", 16, b"4532"),
            (b"4111-1111-1111-1111", 16, b"4111"),
            (b"378282246310005", 15, b"3782"),
            (b"6011000000000004", 16, b"6011"),
        ];
        for (input, expected_len, expected_bin) in cases {
            let cc = fake_cc_luhn_realistic(input);
            assert_eq!(cc.len(), *expected_len, "len mismatch: {}", cc);
            assert!(
                cc.starts_with(std::str::from_utf8(expected_bin).unwrap()),
                "bin mismatch: {}",
                cc
            );
            // luhn valid
            let digits: Vec<u8> = cc.bytes().map(|b| b - b'0').collect();
            let sum: u32 = digits
                .iter()
                .rev()
                .enumerate()
                .map(|(i, &d)| {
                    if i % 2 == 1 {
                        let v = d as u32 * 2;
                        if v > 9 { v - 9 } else { v }
                    } else {
                        d as u32
                    }
                })
                .sum();
            assert_eq!(sum % 10, 0, "luhn invalid: {}", cc);
        }
    }

    #[test]
    fn test_realistic_api_key_preserves_separators_and_length() {
        let input = b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fake = fake_api_key_realistic(input);
        assert_eq!(fake.len(), input.len());
        // separator positions preserved
        for (i, b) in input.iter().enumerate() {
            if !b.is_ascii_alphanumeric() {
                assert_eq!(
                    fake.as_bytes()[i],
                    *b,
                    "separator at pos {} not preserved",
                    i
                );
            }
        }
        assert!(!fake.to_lowercase().contains("bleep"));
    }

    #[test]
    fn test_realistic_url_cred_preserves_host_no_marker() {
        let r = fake_url_cred_realistic("https://admin:secret@api.real-corp.com/v1");
        assert!(
            r.contains("api.real-corp.com"),
            "host must be preserved: {}",
            r
        );
        assert!(!r.contains("bleep"));
        assert!(!r.contains("admin:secret"));
    }

    // ── db conn classifier ───────────────────────────────────────────────────

    #[test]
    fn test_classify_db_conn() {
        assert_eq!(
            classify_db_conn("postgresql://u:p@h:5432/db"),
            DbConnFormat::Url
        );
        assert_eq!(classify_db_conn("mysql://u:p@h/db"), DbConnFormat::Url);
        assert_eq!(
            classify_db_conn("mongodb+srv://u:p@cluster.mongodb.net/db"),
            DbConnFormat::Url
        );
        assert_eq!(
            classify_db_conn("jdbc:postgresql://h:5432/db"),
            DbConnFormat::Jdbc
        );
        assert_eq!(
            classify_db_conn("Server=h;Database=d;User Id=u;Password=p;"),
            DbConnFormat::AdoNet
        );
        assert_eq!(
            classify_db_conn("Driver={SQL Server};Server=h;Database=d;Uid=u;Pwd=p;"),
            DbConnFormat::Odbc
        );
        assert_eq!(
            classify_db_conn("host=localhost port=5432 user=u password=p dbname=d"),
            DbConnFormat::LibpqKv
        );
        assert_eq!(
            classify_db_conn(
                "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=h)(PORT=1521))(CONNECT_DATA=(SID=d)))"
            ),
            DbConnFormat::OracleTns
        );
        assert_eq!(classify_db_conn(""), DbConnFormat::Unknown);
    }

    #[test]
    fn test_realistic_db_conn_url() {
        let r =
            fake_db_conn_realistic("postgresql://realuser:realpass@db.realcorp.com:5432/realdb");
        assert!(r.starts_with("postgresql://"), "got {}", r);
        assert!(r.contains(".example.com"), "got {}", r);
        assert!(!r.contains("realuser"));
        assert!(!r.contains("realpass"));
        assert!(!r.contains("bleep"));
    }

    #[test]
    fn test_realistic_db_conn_jdbc() {
        let r = fake_db_conn_realistic("jdbc:postgresql://db.real.com:5432/prod");
        assert!(r.starts_with("jdbc:postgresql://"), "got {}", r);
        assert!(!r.contains("db.real.com"));
        assert!(!r.contains("bleep"));
    }

    #[test]
    fn test_realistic_db_conn_adonet() {
        let r = fake_db_conn_realistic(
            "Server=db.real.com;Database=prod;User Id=admin;Password=s3cr3t;",
        );
        assert!(r.contains(".example.com"), "host must change: {}", r);
        assert!(!r.contains("admin"), "user must change: {}", r);
        assert!(!r.contains("s3cr3t"), "pass must change: {}", r);
        assert!(!r.contains("bleep"));
        assert!(r.contains("Database="), "non-secret keys preserved: {}", r);
    }

    #[test]
    fn test_realistic_db_conn_odbc() {
        let r = fake_db_conn_realistic(
            "Driver={SQL Server};Server=db.real.com;Database=prod;Uid=admin;Pwd=s3cr3t;",
        );
        assert!(r.contains("Driver="), "Driver key must be preserved: {}", r);
        assert!(!r.contains("admin"));
        assert!(!r.contains("s3cr3t"));
        assert!(!r.contains("bleep"));
    }

    #[test]
    fn test_realistic_db_conn_libpq() {
        let r = fake_db_conn_realistic(
            "host=db.real.com port=5432 user=admin password=s3cr3t dbname=prod",
        );
        assert!(r.contains(".example.com"), "host must change: {}", r);
        assert!(!r.contains("admin"), "got {}", r);
        assert!(!r.contains("s3cr3t"), "got {}", r);
        assert!(r.contains("port=5432"), "non-secret keys preserved: {}", r);
        assert!(!r.contains("bleep"));
    }

    #[test]
    fn test_realistic_db_conn_oracle_tns() {
        let r = fake_db_conn_realistic(
            "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.real.com)(PORT=1521))(CONNECT_DATA=(SID=PROD))(SECURITY=(USER=admin)(PASSWORD=s3cr3t)))",
        );
        assert!(r.contains(".example.com"), "host must change: {}", r);
        assert!(!r.contains("db.real.com"));
        assert!(!r.contains("admin"));
        assert!(!r.contains("s3cr3t"));
        assert!(
            r.contains("PROTOCOL=TCP"),
            "non-secret keys preserved: {}",
            r
        );
        assert!(!r.contains("bleep"));
    }

    // ── shared invariants ────────────────────────────────────────────────────

    #[test]
    fn test_fake_uuid_format() {
        let u = fake_uuid();
        let re = regex::Regex::new(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .unwrap();
        assert!(re.is_match(&u), "got {}", u);
    }

    #[test]
    fn test_generic_random_same_length() {
        let orig = b"ABCDEF12";
        let result = fake_generic_random(orig);
        assert_eq!(result.len(), orig.len());
    }

    #[test]
    fn test_generic_random_digit_only() {
        let orig = b"123456";
        let result = fake_generic_random(orig);
        assert_eq!(result.len(), 6);
        assert!(result.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn test_fpe_numeric_same_length() {
        let orig = b"123456789";
        let result = fake_fpe_numeric(orig);
        assert_eq!(result.len(), orig.len());
        assert!(result.bytes().all(|b| b.is_ascii_digit()));
    }

    // ── JSON safety across all replacers (both modes) ────────────────────────

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
            (
                "faker_github_pat",
                b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
            ),
            ("faker_jwt", b"eyJ0.eyJ1.sig"),
            ("faker_api_key", b"abc123def456abc123def456abc123de"),
            ("faker_db_conn", b"postgresql://user:pass@host:5432/db"),
            (
                "faker_db_conn",
                b"Server=h;Database=d;User Id=u;Password=p;",
            ),
            (
                "faker_db_conn",
                b"host=localhost port=5432 user=u password=p",
            ),
            ("faker_db_conn", b"jdbc:postgresql://host:5432/db"),
            ("faker_url_cred", b"https://admin:pass@api.example.com/v1"),
            ("fpe_numeric", b"123456789"),
            ("generic_random", b"ABCDEF1234"),
        ];
        for (rt, original) in &types {
            let fake = generate(rt, "test-rule", original, None);
            let json_str = format!("\"{}\"", fake.replace('\\', "\\\\").replace('"', "\\\""));
            serde_json::from_str::<serde_json::Value>(&json_str).unwrap_or_else(|e| {
                panic!("{} produced non-JSON-safe value {:?}: {}", rt, fake, e)
            });
        }
    }
}
