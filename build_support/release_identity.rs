//! The single build-boundary full release identity invariant.
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ffi::OsStr, fmt, fs, path::Path};

pub fn resolve(base: &str, explicit: Option<&OsStr>) -> Result<String, String> {
    canonical_version(base)?;
    if let Some(value) = explicit {
        let value = value.to_str().ok_or("AG_FULL_VERSION must be valid text")?;
        if value != base {
            return Err(format!("AG_FULL_VERSION must exactly match Cargo version {base}"));
        }
    }
    Ok(base.to_owned())
}

const ACCEPTANCE_HEADER: &str = "ag-release-acceptance\t1";
pub const PUBLIC_RELEASE_PROFILE: &str = "public-release";
pub const PERSONAL_RELEASE_PROFILE: &str = "personal-release";
const WINDOWS_RELEASE_TARGET: &str = "x86_64-pc-windows-msvc";
const RELEASE_TARGETS: [&str; 3] = [WINDOWS_RELEASE_TARGET, "x86_64-apple-darwin", "aarch64-apple-darwin"];

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().any(|byte| byte != b'0')
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_version(value: &str) -> Result<[u64; 3], String> {
    let parts = value.split('.').collect::<Vec<_>>();
    let mut version = [0; 3];
    if parts.len() != version.len() { return Err("Antigravity version requires three numeric fields".into()); }
    for (number, part) in version.iter_mut().zip(parts) {
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Antigravity version is not canonical decimal".into());
        }
        *number = part.parse().map_err(|_| "Antigravity numeric version overflow")?;
    }
    Ok(version)
}

fn accepted_vendor_version(value: &str, target: &str) -> Result<[u64; 3], String> {
    // A Windows file version can append a zero revision to the vendor version.
    let normalized = if target == WINDOWS_RELEASE_TARGET && value.split('.').count() == 4 {
        value.strip_suffix(".0").ok_or("Windows Antigravity version requires an exact zero fourth field")?
    } else {
        value
    };
    canonical_version(normalized)
}

/// Receive maintainer-selected acceptance evidence for an independently
/// verified build-input snapshot. Each row references actual platform QA.
pub fn accepted_public_version(record: &[u8], source_sha256: &str, profile: &str, target: &str,
    mut receive_evidence: impl FnMut(&str) -> Result<Vec<u8>, String>) -> Result<String, String> {
    if !is_sha256(source_sha256) || !RELEASE_TARGETS.contains(&target)
        || !matches!(profile, PUBLIC_RELEASE_PROFILE | PERSONAL_RELEASE_PROFILE) {
        return Err("public release requires a verified source snapshot, exact profile and supported target".into());
    }
    let text = std::str::from_utf8(record).map_err(|_| "release acceptance must be valid UTF-8")?;
    let mut lines = text.lines();
    if lines.next() != Some(ACCEPTANCE_HEADER) { return Err("release acceptance schema differs".into()); }
    if lines.next().and_then(|line| line.strip_prefix("source\t")) != Some(source_sha256) {
        return Err("release acceptance source differs from the verified snapshot".into());
    }
    if lines.next().and_then(|line| line.strip_prefix("profile\t")) != Some(profile) {
        return Err("release acceptance profile differs from the selected build profile".into());
    }
    let mut matrix = BTreeMap::<[u64; 3], [bool; RELEASE_TARGETS.len()]>::new();
    for line in lines {
        let mut fields = line.split('\t');
        let (Some("accepted"), Some(version), Some(platform), Some(path), Some(evidence), None) =
            (fields.next(), fields.next(), fields.next(), fields.next(), fields.next(), fields.next()) else {
                return Err("malformed public release acceptance row".into());
            };
        if !is_sha256(evidence) { return Err("platform acceptance evidence SHA-256 invalid".into()); }
        validate_evidence_path(path)?;
        let platform_index = RELEASE_TARGETS.iter().position(|value| *value == platform)
            .ok_or("unknown public release acceptance target")?;
        let accepted = matrix.entry(accepted_vendor_version(version, platform)?).or_default();
        if std::mem::replace(&mut accepted[platform_index], true) {
            return Err("duplicate or conflicting public release acceptance row".into());
        }
        if sha256(&receive_evidence(path)?) != evidence {
            return Err("platform acceptance receipt bytes differ from the approved record".into());
        }
    }
    if matrix.values().any(|platforms| platforms.contains(&false)) {
        return Err("partial public release acceptance matrix".into());
    }
    let ([major, minor, patch], _) = matrix.last_key_value().ok_or("public release acceptance matrix is empty")?;
    Ok(format!("{major}.{minor}.{patch}"))
}

pub fn require_public_projection(accepted: &str, base: &str, explicit: Option<&OsStr>) -> Result<(), String> {
    if accepted != base {
        return Err(format!("Cargo version {base} differs from accepted Antigravity version {accepted}"));
    }
    resolve(base, explicit).map(|_| ())
}

// The cross-platform source bundle uses only these ordinary build-input paths.
const SOURCE_FILES: &[&str] = &[
    "Cargo.lock", "Cargo.toml", "LICENSE", "README.md", "build.rs", "build_rust.py", "icon.ico", "tui.ps1", "tui.sh",
];
const SOURCE_TREES: &[&str] = &[".cargo", "assets", "build_support", "linux", "macos", "src", "tests", "wsl"];

struct SourceManifest(BTreeMap<String, String>);
impl<'de> Deserialize<'de> for SourceManifest {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct ManifestVisitor;
        impl<'de> Visitor<'de> for ManifestVisitor {
            type Value = SourceManifest;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object mapping unique source paths to SHA-256 digests")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut files = BTreeMap::new();
                while let Some((path, digest)) = input.next_entry::<String, String>()? {
                    if !is_sha256(&digest) { return Err(de::Error::custom("source file SHA-256 invalid")); }
                    if files.insert(path, digest).is_some() { return Err(de::Error::custom("duplicate source path")); }
                }
                Ok(SourceManifest(files))
            }
        }
        input.deserialize_map(ManifestVisitor)
    }
}

pub fn sha256(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

fn ordinary(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return Err("release input is a reparse point".into()); }
    }
    if metadata.file_type().is_symlink() { return Err("release input is a symbolic link".into()); }
    Ok(metadata)
}

pub fn read_release_input(path: &Path) -> Result<Vec<u8>, String> {
    if !ordinary(path)?.is_file() { return Err("release input is not an ordinary file".into()); }
    fs::read(path).map_err(|error| error.to_string())
}

fn validate_evidence_path(path: &str) -> Result<(), String> {
    if path.split('/').any(|part| part.is_empty() || matches!(part, "." | "..") || part.ends_with('.')
        || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))) {
        return Err("platform acceptance receipt path must be ordinary and relative".into());
    }
    Ok(())
}

pub fn read_platform_receipt(accepted_record: &Path, path: &str) -> Result<Vec<u8>, String> {
    validate_evidence_path(path)?;
    let parent = accepted_record.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !ordinary(parent)?.is_dir() { return Err("platform receipt root is not an ordinary directory".into()); }
    let mut entry = parent.to_owned();
    let mut components = path.split('/').peekable();
    while let Some(component) = components.next() {
        entry.push(component);
        if components.peek().is_some() && !ordinary(&entry)?.is_dir() {
            return Err("platform receipt ancestor is not an ordinary directory".into());
        }
    }
    read_release_input(&entry)
}

fn verify_source_file(root: &Path, relative: &str, remaining: &mut BTreeMap<String, String>) -> Result<(), String> {
    let expected = remaining.remove(relative).ok_or("release source manifest omits an ordinary source file")?;
    if sha256(&read_release_input(&root.join(relative))?) != expected {
        return Err(format!("release source file digest differs: {relative}"));
    }
    Ok(())
}

fn verify_source_tree(root: &Path, relative: &str, remaining: &mut BTreeMap<String, String>) -> Result<(), String> {
    let directory = root.join(relative);
    if !ordinary(&directory)?.is_dir() { return Err("release input tree is not an ordinary directory".into()); }
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("source name must be UTF-8")?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) {
            return Err("source name is outside the ordinary source snapshot format".into());
        }
        let child = format!("{relative}/{name}");
        if ordinary(&entry.path())?.is_dir() {
            verify_source_tree(root, &child, remaining)?;
        } else {
            verify_source_file(root, &child, remaining)?;
        }
    }
    Ok(())
}

/// Verify the actual portable cohort, including additional or missing files.
/// The source identity is the SHA-256 of the compact, sorted JSON digest map.
pub fn verify_source_snapshot(root: &Path, manifest: &[u8]) -> Result<String, String> {
    let SourceManifest(declared) = serde_json::from_slice(manifest)
        .map_err(|error| format!("release source manifest invalid: {error}"))?;
    let mut remaining = declared.clone();
    for relative in SOURCE_FILES { verify_source_file(root, relative, &mut remaining)?; }
    for relative in SOURCE_TREES { verify_source_tree(root, relative, &mut remaining)?; }
    if !remaining.is_empty() { return Err("release source manifest contains missing or unsupported paths".into()); }
    Ok(sha256(&serde_json::to_vec(&declared).map_err(|error| error.to_string())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_uses_exact_canonical_cargo_version() {
        let base = "8.4.1";
        assert_eq!(resolve(base, None).unwrap(), base);
        assert_eq!(resolve(base, Some(OsStr::new(base))).unwrap(), base);
        for bad in ["", " 8.4.1", "8.4.1\n", "8.4.10", "v8.4.1", "8.4.1-macos.1", "8.4.1_1", "8.4.1.0"] {
            assert!(resolve(base, Some(OsStr::new(bad))).is_err(), "{bad:?}");
        }
        for bad_base in ["8.4", "8.04.1", "8.4.1.0", "8.4.1-beta.1"] {
            assert!(resolve(bad_base, None).is_err(), "{bad_base:?}");
        }
    }
    #[cfg(windows)]
    #[test]
    fn non_text_override_is_not_absence() {
        use std::os::windows::ffi::OsStringExt;
        let bad = std::ffi::OsString::from_wide(&[0xd800]);
        assert!(resolve("8.4.1", Some(&bad)).unwrap_err().contains("valid text"));
    }

    fn acceptance(source: &str, versions: &[&str]) -> String {
        let mut record = format!("{ACCEPTANCE_HEADER}\nsource\t{source}\nprofile\t{PUBLIC_RELEASE_PROFILE}\n");
        for version in versions {
            for platform in RELEASE_TARGETS {
                let path = format!("{version}/{platform}.receipt");
                record.push_str(&format!("accepted\t{version}\t{platform}\t{path}\t{}\n",
                    sha256(&synthetic_receipt(&path).unwrap())));
            }
        }
        record
    }

    fn synthetic_receipt(path: &str) -> Result<Vec<u8>, String> {
        Ok(format!("synthetic test fixture for {path}").into_bytes())
    }

    #[test]
    fn public_release_uses_latest_exact_common_acceptance() {
        let source = "a".repeat(64);
        let record = acceptance(&source, &["8.10.1", "8.9.24"]);
        for target in RELEASE_TARGETS {
            assert_eq!(accepted_public_version(record.as_bytes(), &source, PUBLIC_RELEASE_PROFILE, target, synthetic_receipt).unwrap(), "8.10.1");
            let personal = record.replace(PUBLIC_RELEASE_PROFILE, PERSONAL_RELEASE_PROFILE);
            assert_eq!(accepted_public_version(personal.as_bytes(), &source, PERSONAL_RELEASE_PROFILE, target, synthetic_receipt).unwrap(), "8.10.1");
        }
        assert!(accepted_public_version(record.as_bytes(), &source, PUBLIC_RELEASE_PROFILE, "x86_64-unknown-linux-gnu", synthetic_receipt).is_err());
        assert!(require_public_projection("8.10.1", "8.9.24", None).is_err());
        assert!(require_public_projection("8.10.1", "8.10.1", Some(OsStr::new("8.10.1-macos.4"))).is_err());
        require_public_projection("8.10.1", "8.10.1", None).unwrap();
    }

    #[test]
    fn public_release_combines_windows_zero_revision_with_the_mac_version() {
        let source = "a".repeat(64);
        let base = acceptance(&source, &["8.9.24"]);
        let windows_row = "accepted\t8.9.24\tx86_64-pc-windows-msvc";
        let normalized = base.replace(windows_row, "accepted\t8.9.24.0\tx86_64-pc-windows-msvc");
        let received = |record: &str| accepted_public_version(record.as_bytes(), &source,
            PUBLIC_RELEASE_PROFILE, WINDOWS_RELEASE_TARGET, synthetic_receipt);
        assert_eq!(received(&normalized).unwrap(), "8.9.24");
        assert!(received(&normalized.replace("8.9.24.0\t", "8.9.24.1\t")).is_err());
        assert!(received(&base.replace("accepted\t8.9.24\taarch64", "accepted\t8.9.24.0\taarch64")).is_err());
        let duplicate = base.lines().find(|line| line.starts_with(windows_row)).unwrap();
        assert!(received(&format!("{normalized}{duplicate}\n")).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn public_release_rejects_incomplete_malformed_or_mixed_evidence() {
        let source = "a".repeat(64);
        let target = RELEASE_TARGETS[0];
        let receive = |value: &str| accepted_public_version(value.as_bytes(), &source, PUBLIC_RELEASE_PROFILE, target, synthetic_receipt);
        let record = acceptance(&source, &["8.9.24"]);
        assert!(receive(&acceptance(&source, &[])).is_err());
        assert!(receive(&acceptance(&"b".repeat(64), &["8.9.24"])).is_err());
        assert!(receive(&record.replace(PUBLIC_RELEASE_PROFILE, "personal-release")).is_err());
        assert!(receive(&record.replace("accepted\t8.9.24\t", "accepted\t8.09.24\t"))
            .unwrap_err().contains("not canonical decimal"));
        assert!(receive(&record.replace("accepted\t8.9.24\t", "accepted\t8.9.18446744073709551616\t"))
            .unwrap_err().contains("numeric version overflow"));
        assert!(receive(&record.replace("aarch64-apple-darwin", "x86_64-apple-darwin")).is_err());
        assert!(receive(&record.replace("aarch64-apple-darwin", "aarch64-pc-windows-msvc")).is_err());
        let proof = sha256(&synthetic_receipt("8.9.24/x86_64-pc-windows-msvc.receipt").unwrap());
        assert!(receive(&record.replace(&proof, &"0".repeat(64))).is_err());
        assert!(receive(&record.replace("8.9.24/x86_64-pc-windows-msvc.receipt", "../unowned.receipt")).is_err());
        assert!(accepted_public_version(record.as_bytes(), &source, PUBLIC_RELEASE_PROFILE, target,
            |_| Ok(b"unrelated bytes".to_vec())).unwrap_err().contains("receipt bytes differ"));
        assert!(accepted_public_version(record.as_bytes(), &source, PUBLIC_RELEASE_PROFILE, target,
            |_| Err("fixture receipt missing".into())).unwrap_err().contains("receipt missing"));
        let partial = record.lines().take(5).collect::<Vec<_>>().join("\n");
        assert!(receive(&partial).is_err());
        let mixed = record.replace("accepted\t8.9.24\taarch64", "accepted\t8.10.1\taarch64");
        assert!(receive(&mixed).is_err());
    }

    #[test]
    fn source_manifest_requires_unique_string_paths_and_canonical_digests() {
        let digest = "e".repeat(64);
        let unique = format!(r#"{{"src/main.rs":"{digest}"}}"#);
        let SourceManifest(entries) = serde_json::from_str(&unique).unwrap();
        assert_eq!(entries["src/main.rs"], digest);
        let duplicate = format!(r#"{{"src/main.rs":"{digest}","src/main.rs":"{digest}"}}"#);
        assert!(serde_json::from_str::<SourceManifest>(&duplicate).is_err());
        assert!(serde_json::from_str::<SourceManifest>(r#"{"src/main.rs":true}"#).is_err());
        assert!(serde_json::from_str::<SourceManifest>(&unique.replace(&digest, &"E".repeat(64))).is_err());
    }
}
