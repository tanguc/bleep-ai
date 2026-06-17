//! Per-install MITM certificate authority.
//!
//! Bleep MITMs `*.anthropic.com` to redact prompts, which requires a local CA
//! whose private key signs the on-the-fly leaf certs. That key is the crown
//! jewel: anything that trusts the CA (the user's claude process, via
//! `NODE_EXTRA_CA_CERTS`) can be impersonated by whoever holds the key.
//!
//! Earlier builds `include_str!`'d a single CA + key into the binary. For an
//! open-source build that is a non-starter — the private key would be public,
//! so every install would trust a key the whole world has. Instead we generate
//! a fresh CA per machine on first launch and store it under `~/.bleep/ca/`
//! (key `0600`, dir `0700`). The key never leaves the machine and never enters
//! the repo.

use std::path::{Path, PathBuf};

/// Directory holding the per-install CA (`~/.bleep/ca/`).
fn ca_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".bleep").join("ca")
}

/// Load the per-install CA, generating it on first run.
///
/// Returns `(cert_pem, key_pem)`. The cert PEM is what client TLS stacks must
/// trust (the installer/wrapper points `NODE_EXTRA_CA_CERTS` & friends at
/// `~/.bleep/ca/cert.pem`); the key PEM signs leaf certs inside the proxy.
pub fn ensure_ca() -> std::io::Result<(String, String)> {
    let dir = ca_dir();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        return Ok((cert_pem, key_pem));
    }

    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let (cert_pem, key_pem) = generate_ca().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("CA generation failed: {e}"))
    })?;

    // key first, locked down, before the cert exists — never leave a window
    // where the cert is present but the key is world-readable.
    write_private(&key_path, &key_pem)?;
    std::fs::write(&cert_path, &cert_pem)?;
    println!(
        "[ca] generated per-install MITM CA at {} (trust {})",
        dir.display(),
        cert_path.display()
    );
    Ok((cert_pem, key_pem))
}

/// Write a file with `0600` perms on Unix (owner read/write only).
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Generate a fresh self-signed CA (ECDSA P-256). Returns `(cert_pem, key_pem)`.
fn generate_ca() -> Result<(String, String), rcgen::Error> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let mut params = CertificateParams::new(Vec::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "bleep local CA");
    dn.push(DnType::OrganizationName, "bleep");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}
