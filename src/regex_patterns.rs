// deprecated: use src/patterns/mod.rs instead; will be removed in phase cleanup

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RegexPatterns {
    pub rules: Vec<RegexPatternRule>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RegexPatternRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub regex: String,
    pub description: String,
}

use std::borrow::Cow;
use std::sync::LazyLock;

use bytes::Bytes;
use regex::Regex;
use regex::bytes::Regex as BytesRegex;
use serde::Serialize;

pub static COMBINED: LazyLock<BytesRegex> = LazyLock::new(|| {
    let patterns_file = include_str!("../rules/sensitive-patterns.yaml").to_string();

    let regex_patterns_obj: RegexPatterns =
        serde_yml::from_str(&patterns_file).expect("Failed to parse regex patterns file");

    let combined_pattern = regex_patterns_obj
        .rules
        .iter()
        .map(|rule| format!("(?:{})", rule.regex))
        .collect::<Vec<_>>()
        .join("|");

    BytesRegex::new(&combined_pattern).expect("Failed to compile combined regex")
});

pub static RULES: LazyLock<Vec<(RegexPatternRule, BytesRegex)>> = LazyLock::new(|| {
    let patterns_file = include_str!("../rules/sensitive-patterns.yaml").to_string();

    let regex_patterns_obj: RegexPatterns =
        serde_yml::from_str(&patterns_file).expect("Failed to parse regex patterns file");

    regex_patterns_obj
        .rules
        .iter()
        .map(|rule| {
            let compiled_regex = BytesRegex::new(&rule.regex).unwrap_or_else(|e| {
                panic!(
                    "Failed to compile regex for rule '{}' ({}): {}",
                    rule.id, rule.regex, e
                )
            });
            (rule.clone(), compiled_regex)
        })
        .collect()
});

#[derive(Debug, Clone, Serialize)]
pub struct MatchedRule {
    pub rule: RegexPatternRule,
    pub matches: Vec<Vec<u8>>,
}

pub async fn do_match(body: Bytes) -> (Bytes, Option<Vec<MatchedRule>>) {
    use std::time::Instant;

    let total_start = Instant::now();
    let body_len = body.len();

    let mut current = body.to_vec();

    // fast pre-check — skip full scan if no pattern matches at all
    if !COMBINED.is_match(&current) {
        return (body, None);
    }

    // only init if matched no need to pay cost of building vec if no matches
    let mut matched_rules: Vec<MatchedRule> = Vec::new();
    for (rule, regex) in RULES.iter() {
        let rule_start = Instant::now();
        let matched = regex.is_match(&current);
        let rule_elapsed = rule_start.elapsed();

        if matched {
            // capture all matches for this rule before replacement
            {
                let caps: Vec<_> = regex
                    .captures_iter(&current)
                    .map(|cap| cap.get_match().as_bytes().to_owned())
                    .collect();
                matched_rules.push(MatchedRule {
                    rule: rule.clone(),
                    matches: caps,
                });
            }

            let replace_start = Instant::now();
            let replacement = format!("[REDACTED:{}]", rule.id);
            current = regex
                .replace_all(&current, replacement.as_bytes())
                .into_owned();
            let replace_elapsed = replace_start.elapsed();

            println!(
                "[scan] HIT  {:24} | match: {:>8.3}us | replace: {:>8.3}us | {}",
                rule.id,
                rule_elapsed.as_nanos() as f64 / 1000.0,
                replace_elapsed.as_nanos() as f64 / 1000.0,
                rule.severity,
            );
        } else {
            println!(
                "[scan] MISS {:24} | match: {:>8.3}us",
                rule.id,
                rule_elapsed.as_nanos() as f64 / 1000.0,
            );
        }
    }

    let total_elapsed = total_start.elapsed();
    println!(
        "[scan] done | {} bytes | {} rules checked | {} hits | total: {}.{:03}ms ({}us)",
        body_len,
        RULES.len(),
        matched_rules.len(),
        total_elapsed.as_millis(),
        total_elapsed.as_micros() % 1000,
        total_elapsed.as_micros(),
    );

    if !matched_rules.is_empty() {
        (Bytes::from(current), Some(matched_rules))
    } else {
        (body, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_do_match_with_no_sensitive_data() {
        let body = Bytes::from("this is safe content");
        let result = do_match(body).await;
        assert_eq!(result.0, Bytes::from("this is safe content"));
    }

    #[tokio::test]
    async fn test_do_match_redacts_github_token() {
        let body = Bytes::from("my token is ghp_ABCDEFabcdef123456789012345678901234");
        let result = do_match(body).await;
        assert_eq!(result.0, Bytes::from("my token is [REDACTED:github-token]"));
    }

    #[test]
    fn test_regex_patterns_load() {
        let rules = &RULES;
        assert!(!rules.is_empty(), "Rules should be loaded");
    }

    #[tokio::test]
    async fn bench_do_match_hot_path() {
        use std::time::Instant;

        let input_with_secret = Bytes::from(
            "my token is ghp_ABCDEFabcdef123456789012345678901234 and email is test@example.com",
        );
        let input_clean = Bytes::from(
            "this is perfectly normal text with no secrets or pii at all, just regular code review",
        );

        // warmup: force compilation + fill cpu caches
        let _ = RULES.len();
        for _ in 0..100 {
            let _ = do_match(input_with_secret.clone()).await;
            let _ = do_match(input_clean.clone()).await;
        }

        let iterations = 1000;

        // hot bench: with secrets
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = do_match(input_with_secret.clone()).await;
        }
        let with_secret = start.elapsed();

        // hot bench: clean input
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = do_match(input_clean.clone()).await;
        }
        let clean = start.elapsed();

        println!("\n=== HOT PATH BENCHMARK ({} iterations) ===", iterations);
        println!(
            "with secrets ({} bytes): avg {:.3}us per call ({:.3}ms total)",
            input_with_secret.len(),
            with_secret.as_nanos() as f64 / iterations as f64 / 1000.0,
            with_secret.as_secs_f64() * 1000.0,
        );
        println!(
            "clean input  ({} bytes): avg {:.3}us per call ({:.3}ms total)",
            input_clean.len(),
            clean.as_nanos() as f64 / iterations as f64 / 1000.0,
            clean.as_secs_f64() * 1000.0,
        );
        println!("================================================\n");
    }

    #[tokio::test]
    async fn bench_5000_tokens_1200_rules() {
        use regex::bytes::Regex as BytesRegex;
        use std::time::Instant;

        // ~5000 tokens = ~20KB of text
        let base_text = "The quick brown fox jumps over the lazy dog. This is a typical prompt with some code context and discussion about implementation details. ";
        let mut big_input = String::with_capacity(20_000);
        while big_input.len() < 20_000 {
            big_input.push_str(base_text);
        }
        // sprinkle a secret near the end
        big_input.push_str(" my key is ghp_ABCDEFabcdef123456789012345678901234 done");
        let body = Bytes::from(big_input.clone());

        // build 1200 compiled regexes: 20 real + 1180 realistic filler patterns
        let mut rules_1200: Vec<BytesRegex> = Vec::with_capacity(1200);

        // add real rules
        for (_rule, regex) in RULES.iter() {
            rules_1200.push(regex.clone());
        }

        // add filler patterns that look like real secret/pii patterns
        let filler_patterns = [
            r"GOOG[A-Za-z0-9_-]{20,}",
            r"AIza[A-Za-z0-9_-]{35}",
            r"ya29\.[A-Za-z0-9_-]{50,}",
            r"(?i)twilio[_\s]*auth[_\s]*token\s*[=:]\s*[a-f0-9]{32}",
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            r"(?i)mailgun[_\s]*api[_\s]*key\s*[=:]\s*key-[a-f0-9]{32}",
            r"sq0csp-[A-Za-z0-9_-]{43}",
            r"(?i)datadog[_\s]*api[_\s]*key\s*[=:]\s*[a-f0-9]{32}",
            r"(?i)newrelic[_\s]*license\s*[=:]\s*[a-f0-9]{40}",
            r"npm_[A-Za-z0-9]{36}",
        ];
        while rules_1200.len() < 1200 {
            for pat in &filler_patterns {
                if rules_1200.len() >= 1200 {
                    break;
                }
                rules_1200.push(BytesRegex::new(pat).unwrap());
            }
        }

        // warmup
        let body_bytes = body.to_vec();
        for _ in 0..10 {
            for regex in &rules_1200 {
                let _ = regex.is_match(&body_bytes);
            }
        }

        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            let scan_body = body.to_vec();
            for regex in &rules_1200 {
                let _ = regex.is_match(&scan_body);
            }
        }
        let elapsed = start.elapsed();

        println!(
            "\n=== 5000 TOKENS x 1200 RULES BENCHMARK ({} iterations) ===",
            iterations
        );
        println!(
            "input: {} bytes (~5000 tokens), {} rules",
            body.len(),
            rules_1200.len()
        );
        println!(
            "avg per call: {:.3}ms ({:.0}us)",
            elapsed.as_secs_f64() * 1000.0 / iterations as f64,
            elapsed.as_micros() as f64 / iterations as f64,
        );
        println!(
            "avg per rule: {:.3}us",
            elapsed.as_nanos() as f64 / iterations as f64 / rules_1200.len() as f64 / 1000.0,
        );
        println!("==========================================================\n");
    }
}
