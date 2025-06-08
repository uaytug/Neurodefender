use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Represents a malware signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Unique identifier for the signature
    pub id: String,

    /// Signature name
    pub name: String,

    /// Signature description
    pub description: String,

    /// Malware family this signature detects
    pub malware_family: String,

    /// Severity level (critical, high, medium, low)
    pub severity: String,

    /// SHA-256 hash of the malware
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// MD5 hash of the malware (legacy, SHA-256 preferred)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,

    /// Binary pattern to match against
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// References to external resources
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// Tags for categorization
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Date the signature was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Date the signature was last modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

/// Helper for loading and managing malware signatures
pub struct SignatureManager {
    /// Directory containing signature files
    signatures_dir: PathBuf,

    /// Loaded signatures
    signatures: Vec<Signature>,

    /// Hash-based lookup for quick matching
    hash_lookup: HashMap<String, Vec<usize>>,
}

impl SignatureManager {
    /// Create a new signature manager
    pub fn new<P: AsRef<Path>>(signatures_dir: P) -> Result<Self> {
        let dir_path = signatures_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !dir_path.exists() {
            fs::create_dir_all(&dir_path)
                .with_context(|| format!("Failed to create signatures directory: {:?}", dir_path))?;
        }

        let mut manager = Self {
            signatures_dir: dir_path,
            signatures: Vec::new(),
            hash_lookup: HashMap::new(),
        };

        // Load signatures
        manager.load_signatures()?;

        Ok(manager)
    }

    /// Load signatures from the signatures directory
    pub fn load_signatures(&mut self) -> Result<()> {
        self.signatures.clear();
        self.hash_lookup.clear();

        // Check if directory exists
        if !self.signatures_dir.exists() {
            info!("Signatures directory doesn't exist, creating...");
            fs::create_dir_all(&self.signatures_dir)
                .context("Failed to create signatures directory")?;
            return Ok(());
        }

        // Read all signature files
        for entry in fs::read_dir(&self.signatures_dir).context("Failed to read signatures directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            // Only process JSON files
            if path.extension().map_or(false, |ext| ext == "json") {
                match self.load_signature_file(&path) {
                    Ok(signature) => {
                        // Add SHA-256 hash to lookup map
                        if let Some(hash) = &signature.sha256 {
                            let index = self.signatures.len();
                            self.hash_lookup.entry(hash.to_lowercase()).or_insert_with(Vec::new).push(index);
                        }

                        // Add MD5 hash to lookup map
                        if let Some(hash) = &signature.md5 {
                            let index = self.signatures.len();
                            self.hash_lookup.entry(hash.to_lowercase()).or_insert_with(Vec::new).push(index);
                        }

                        // Add the signature
                        self.signatures.push(signature);
                    },
                    Err(e) => warn!("Failed to load signature file {:?}: {}", path, e),
                }
            }
        }

        info!("Loaded {} malware signatures", self.signatures.len());
        Ok(())
    }

    /// Load a single signature file
    fn load_signature_file(&self, path: &PathBuf) -> Result<Signature> {
        // Read file
        let signature_json = fs::read_to_string(path)
            .with_context(|| format!("Failed to read signature file: {:?}", path))?;

        // Parse JSON
        let signature: Signature = serde_json::from_str(&signature_json)
            .with_context(|| format!("Failed to parse signature file: {:?}", path))?;

        Ok(signature)
    }

    /// Add a new signature
    pub fn add_signature(&mut self, signature: Signature) -> Result<()> {
        // Save to file
        let signature_path = self.signatures_dir.join(format!("{}.json", signature.id));
        let signature_json = serde_json::to_string_pretty(&signature)
            .context("Failed to serialize signature to JSON")?;

        fs::write(&signature_path, signature_json)
            .with_context(|| format!("Failed to write signature file: {:?}", signature_path))?;

        // Add SHA-256 hash to lookup map
        if let Some(hash) = &signature.sha256 {
            let index = self.signatures.len();
            self.hash_lookup.entry(hash.to_lowercase()).or_insert_with(Vec::new).push(index);
        }

        // Add MD5 hash to lookup map
        if let Some(hash) = &signature.md5 {
            let index = self.signatures.len();
            self.hash_lookup.entry(hash.to_lowercase()).or_insert_with(Vec::new).push(index);
        }

        // Add the signature
        self.signatures.push(signature);

        Ok(())
    }

    /// Match data against signatures
    pub fn match_data(&self, data: &[u8]) -> Vec<&Signature> {
        let mut matches = Vec::new();

        // Compute hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        // Check if hash matches any signatures
        if let Some(indices) = self.hash_lookup.get(&hash) {
            for &index in indices {
                matches.push(&self.signatures[index]);
            }
        }

        // Check binary patterns if no hash matches
        if matches.is_empty() {
            for signature in &self.signatures {
                if let Some(pattern) = &signature.pattern {
                    // This is a simplified pattern matching logic
                    // In a real system, we would use more sophisticated pattern matching
                    if self.match_pattern(data, pattern) {
                        matches.push(signature);
                    }
                }
            }
        }

        matches
    }

    /// Match a binary pattern against data
    fn match_pattern(&self, data: &[u8], pattern: &str) -> bool {
        // This is a simplified implementation
        // In a real system, we would use YARA or similar for pattern matching

        // Split pattern into bytes
        let mut pattern_bytes = Vec::new();
        let mut wildcards = Vec::new();

        let parts: Vec<&str> = pattern.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "??" {
                // Wildcard
                wildcards.push(i);
                pattern_bytes.push(0);
            } else {
                // Parse hex byte
                match u8::from_str_radix(part, 16) {
                    Ok(b) => pattern_bytes.push(b),
                    Err(_) => {
                        warn!("Invalid pattern byte: {}", part);
                        return false;
                    }
                }
            }
        }

        // Check if pattern is longer than data
        if pattern_bytes.len() > data.len() {
            return false;
        }

        // Try to match pattern at each position in data
        for i in 0..=(data.len() - pattern_bytes.len()) {
            let mut match_found = true;

            for j in 0..pattern_bytes.len() {
                if wildcards.contains(&j) {
                    // Skip wildcards
                    continue;
                }

                if data[i + j] != pattern_bytes[j] {
                    match_found = false;
                    break;
                }
            }

            if match_found {
                return true;
            }
        }

        false
    }

    /// Get all signatures
    pub fn get_signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Get signature by ID
    pub fn get_signature_by_id(&self, id: &str) -> Option<&Signature> {
        self.signatures.iter().find(|s| s.id == id)
    }
}