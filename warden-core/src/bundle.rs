#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::policy::Policy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleLeaf {
    pub path: String,
    pub content_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofElement {
    pub hash: Hash,
    pub is_left: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: Hash,
    pub path: String,
    pub proof: Vec<ProofElement>,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<MerkleLeaf>,
    root: Hash,
    tree: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn build(files: &[(String, Vec<u8>)]) -> Self {
        if files.is_empty() {
            return Self {
                leaves: vec![],
                root: [0u8; 32],
                tree: vec![vec![[0u8; 32]]],
            };
        }

        let mut leaves: Vec<MerkleLeaf> = files
            .iter()
            .map(|(path, content)| MerkleLeaf {
                path: path.clone(),
                content_hash: hash_content(content),
            })
            .collect();

        leaves.sort_by(|a, b| a.path.cmp(&b.path));

        let mut tree: Vec<Vec<Hash>> = vec![leaves.iter().map(|l| l.content_hash).collect()];

        while tree.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let current_level = tree.last().unwrap();
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                next_level.push(hash);
            }

            tree.push(next_level);
        }

        let root = tree
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32]);

        Self { leaves, root, tree }
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn prove(&self, path: &str) -> Option<MerkleProof> {
        let index = self.leaves.iter().position(|l| l.path == path)?;

        let mut proof = Vec::new();
        let mut current_index = index;

        for level in &self.tree[..self.tree.len().saturating_sub(1)] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level.len() {
                proof.push(ProofElement {
                    hash: level[sibling_index],
                    is_left: current_index % 2 == 1,
                });
            }

            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_hash: self.leaves[index].content_hash,
            path: path.to_string(),
            proof,
        })
    }

    pub fn verify(root: &Hash, proof: &MerkleProof) -> bool {
        let mut current = proof.leaf_hash;

        for element in &proof.proof {
            current = if element.is_left {
                hash_pair(&element.hash, &current)
            } else {
                hash_pair(&current, &element.hash)
            };
        }

        &current == root
    }

    pub fn leaves(&self) -> &[MerkleLeaf] {
        &self.leaves
    }
}

fn hash_content(content: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hasher.finalize().into()
}

fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    pub signer: String,
    pub algorithm: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub previous_version: Option<String>,
    pub previous_root_hash: Option<String>,
    pub contents: BundleContents,
    pub merkle_root: String,
    pub signatures: Vec<BundleSignature>,
    pub required_signatures: u32,
    pub valid_signers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleContents {
    pub policies: Vec<String>,
    pub whitelists: Vec<String>,
    pub blacklists: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningPayload {
    pub version: String,
    pub merkle_root: String,
    pub previous_root_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl BundleManifest {
    pub fn signing_payload(&self) -> SigningPayload {
        SigningPayload {
            version: self.version.clone(),
            merkle_root: self.merkle_root.clone(),
            previous_root_hash: self.previous_root_hash.clone(),
            created_at: self.created_at,
        }
    }

    pub fn has_sufficient_signatures(&self) -> bool {
        let valid_count = self
            .signatures
            .iter()
            .filter(|s| self.valid_signers.contains(&s.signer))
            .count();
        valid_count >= self.required_signatures as usize
    }
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub policies: Vec<Policy>,
    pub whitelists: HashMap<String, Vec<String>>,
    pub blacklists: HashMap<String, Vec<String>>,
    pub loaded_at: DateTime<Utc>,
    files: Vec<(String, Vec<u8>)>,
}

impl LoadedBundle {
    pub fn prove_policy(&self, policy_path: &str) -> Option<BundleProof> {
        let tree = MerkleTree::build(&self.files);
        let merkle_proof = tree.prove(policy_path)?;

        Some(BundleProof {
            bundle_version: self.manifest.version.clone(),
            merkle_root: self.manifest.merkle_root.clone(),
            signatures: self.manifest.signatures.clone(),
            policy_proof: merkle_proof,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProof {
    pub bundle_version: String,
    pub merkle_root: String,
    pub signatures: Vec<BundleSignature>,
    pub policy_proof: MerkleProof,
}

#[async_trait::async_trait]
pub trait BundleStore: Send + Sync {
    async fn fetch(&self, bundle_id: &str) -> Result<Vec<u8>>;
    async fn store(&self, bundle_id: &str, data: &[u8]) -> Result<()>;
    async fn list_versions(&self) -> Result<Vec<String>>;
}

#[async_trait::async_trait]
pub trait BundleSigner: Send + Sync {
    async fn sign(&self, payload: &[u8], signer_id: &str) -> Result<Vec<u8>>;
    async fn verify(&self, payload: &[u8], signature: &[u8], signer_id: &str) -> Result<bool>;
    fn get_signer_ids(&self) -> Vec<String>;
}

pub struct BundleLoader<S: BundleStore, V: BundleSigner> {
    store: S,
    signer: V,
    current_bundle: tokio::sync::RwLock<Option<LoadedBundle>>,
}

impl<S: BundleStore, V: BundleSigner> BundleLoader<S, V> {
    pub fn new(store: S, signer: V) -> Self {
        Self {
            store,
            signer,
            current_bundle: tokio::sync::RwLock::new(None),
        }
    }

    pub async fn load(&self, bundle_id: &str) -> Result<LoadedBundle> {
        let bundle_bytes = self.store.fetch(bundle_id).await?;
        let bundle = self.unpack(&bundle_bytes)?;

        if !self.verify_signatures(&bundle.manifest).await? {
            return Err(Error::BundleVerification("Invalid signatures".to_string()));
        }

        let computed_tree = MerkleTree::build(&bundle.files);
        let computed_root = hex::encode(computed_tree.root());
        if computed_root != bundle.manifest.merkle_root {
            return Err(Error::BundleVerification(
                "Merkle root mismatch".to_string(),
            ));
        }

        {
            let current = self.current_bundle.read().await;
            if let Some(ref current) = *current {
                if !is_version_newer(&bundle.manifest.version, &current.manifest.version) {
                    return Err(Error::BundleVerification(
                        "Rollback attempt detected".to_string(),
                    ));
                }
            }
        }

        let loaded = LoadedBundle {
            manifest: bundle.manifest,
            policies: bundle.policies,
            whitelists: bundle.whitelists,
            blacklists: bundle.blacklists,
            loaded_at: Utc::now(),
            files: bundle.files,
        };

        *self.current_bundle.write().await = Some(loaded.clone());

        Ok(loaded)
    }

    pub async fn current(&self) -> Option<LoadedBundle> {
        self.current_bundle.read().await.clone()
    }

    pub async fn prove_policy(&self, policy_path: &str) -> Option<BundleProof> {
        let bundle = self.current_bundle.read().await;
        bundle.as_ref()?.prove_policy(policy_path)
    }

    fn unpack(&self, data: &[u8]) -> Result<UnpackedBundle> {
        let archive: BundleArchive = serde_json::from_slice(data)
            .map_err(|e| Error::BundleVerification(format!("Invalid bundle format: {}", e)))?;

        let mut files = Vec::new();
        for (path, content) in &archive.files {
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, content)
                    .map_err(|e| Error::BundleVerification(format!("Invalid base64: {}", e)))?;
            files.push((path.clone(), decoded));
        }

        let policies = self.parse_policies(&files, &archive.manifest)?;
        let whitelists = self.parse_address_lists(&files, &archive.manifest.contents.whitelists)?;
        let blacklists = self.parse_address_lists(&files, &archive.manifest.contents.blacklists)?;

        Ok(UnpackedBundle {
            manifest: archive.manifest,
            files,
            policies,
            whitelists,
            blacklists,
        })
    }

    fn parse_policies(
        &self,
        files: &[(String, Vec<u8>)],
        manifest: &BundleManifest,
    ) -> Result<Vec<Policy>> {
        let mut policies = Vec::new();
        for policy_path in &manifest.contents.policies {
            let content = files
                .iter()
                .find(|(p, _)| p == policy_path)
                .map(|(_, c)| c)
                .ok_or_else(|| {
                    Error::BundleVerification(format!("Policy not found: {}", policy_path))
                })?;

            let policy: Policy = serde_yaml::from_slice(content)
                .map_err(|e| Error::BundleVerification(format!("Invalid policy YAML: {}", e)))?;
            policies.push(policy);
        }
        Ok(policies)
    }

    fn parse_address_lists(
        &self,
        files: &[(String, Vec<u8>)],
        list_paths: &[String],
    ) -> Result<HashMap<String, Vec<String>>> {
        let mut lists = HashMap::new();
        for list_path in list_paths {
            let content = files
                .iter()
                .find(|(p, _)| p == list_path)
                .map(|(_, c)| c)
                .ok_or_else(|| {
                    Error::BundleVerification(format!("List not found: {}", list_path))
                })?;

            let addresses: Vec<String> = serde_json::from_slice(content).map_err(|e| {
                Error::BundleVerification(format!("Invalid address list JSON: {}", e))
            })?;

            let name = list_path
                .rsplit('/')
                .next()
                .unwrap_or(list_path)
                .trim_end_matches(".json")
                .to_string();
            lists.insert(name, addresses);
        }
        Ok(lists)
    }

    async fn verify_signatures(&self, manifest: &BundleManifest) -> Result<bool> {
        if manifest.signatures.len() < manifest.required_signatures as usize {
            return Ok(false);
        }

        let payload = serde_json::to_vec(&manifest.signing_payload())
            .map_err(|e| Error::BundleVerification(format!("Serialization error: {}", e)))?;

        let mut valid_count = 0;
        for sig in &manifest.signatures {
            if !manifest.valid_signers.contains(&sig.signer) {
                continue;
            }

            let signature_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig.signature)
                    .map_err(|e| {
                        Error::BundleVerification(format!("Invalid signature base64: {}", e))
                    })?;

            if self
                .signer
                .verify(&payload, &signature_bytes, &sig.signer)
                .await?
            {
                valid_count += 1;
            }
        }

        Ok(valid_count >= manifest.required_signatures as usize)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BundleArchive {
    manifest: BundleManifest,
    files: HashMap<String, String>,
}

struct UnpackedBundle {
    manifest: BundleManifest,
    files: Vec<(String, Vec<u8>)>,
    policies: Vec<Policy>,
    whitelists: HashMap<String, Vec<String>>,
    blacklists: HashMap<String, Vec<String>>,
}

fn is_version_newer(new_version: &str, current_version: &str) -> bool {
    let parse_version =
        |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse().ok()).collect() };

    let new_parts = parse_version(new_version);
    let current_parts = parse_version(current_version);
    let max_len = new_parts.len().max(current_parts.len());

    for i in 0..max_len {
        let new = new_parts.get(i).copied().unwrap_or(0);
        let current = current_parts.get(i).copied().unwrap_or(0);
        if new > current {
            return true;
        }
        if new < current {
            return false;
        }
    }

    false
}

pub struct InMemoryBundleStore {
    bundles: tokio::sync::RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryBundleStore {
    pub fn new() -> Self {
        Self {
            bundles: tokio::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBundleStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl BundleStore for InMemoryBundleStore {
    async fn fetch(&self, bundle_id: &str) -> Result<Vec<u8>> {
        self.bundles
            .read()
            .await
            .get(bundle_id)
            .cloned()
            .ok_or_else(|| Error::BundleVerification(format!("Bundle not found: {}", bundle_id)))
    }

    async fn store(&self, bundle_id: &str, data: &[u8]) -> Result<()> {
        self.bundles
            .write()
            .await
            .insert(bundle_id.to_string(), data.to_vec());
        Ok(())
    }

    async fn list_versions(&self) -> Result<Vec<String>> {
        Ok(self.bundles.read().await.keys().cloned().collect())
    }
}

pub struct MockBundleSigner {
    keys: HashMap<String, Vec<u8>>,
}

impl MockBundleSigner {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn with_key(mut self, signer_id: &str, key: Vec<u8>) -> Self {
        self.keys.insert(signer_id.to_string(), key);
        self
    }
}

impl Default for MockBundleSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl BundleSigner for MockBundleSigner {
    async fn sign(&self, payload: &[u8], signer_id: &str) -> Result<Vec<u8>> {
        let key = self
            .keys
            .get(signer_id)
            .ok_or_else(|| Error::BundleVerification(format!("Unknown signer: {}", signer_id)))?;

        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.update(key);
        Ok(hasher.finalize().to_vec())
    }

    async fn verify(&self, payload: &[u8], signature: &[u8], signer_id: &str) -> Result<bool> {
        let expected = self.sign(payload, signer_id).await?;
        Ok(bool::from(expected.ct_eq(signature)))
    }

    fn get_signer_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_file() {
        let files = vec![("policy.yaml".to_string(), b"content".to_vec())];
        let tree = MerkleTree::build(&files);

        assert_eq!(tree.leaves().len(), 1);
        let proof = tree.prove("policy.yaml").unwrap();
        assert!(MerkleTree::verify(&tree.root(), &proof));
    }

    #[test]
    fn test_merkle_tree_multiple_files() {
        let files = vec![
            ("a.yaml".to_string(), b"content a".to_vec()),
            ("b.yaml".to_string(), b"content b".to_vec()),
            ("c.yaml".to_string(), b"content c".to_vec()),
        ];
        let tree = MerkleTree::build(&files);

        assert_eq!(tree.leaves().len(), 3);

        for (path, _) in &files {
            let proof = tree.prove(path).unwrap();
            assert!(MerkleTree::verify(&tree.root(), &proof));
        }
    }

    #[test]
    fn test_merkle_tree_deterministic() {
        let files1 = vec![
            ("b.yaml".to_string(), b"b".to_vec()),
            ("a.yaml".to_string(), b"a".to_vec()),
        ];
        let files2 = vec![
            ("a.yaml".to_string(), b"a".to_vec()),
            ("b.yaml".to_string(), b"b".to_vec()),
        ];

        let tree1 = MerkleTree::build(&files1);
        let tree2 = MerkleTree::build(&files2);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_version_comparison() {
        assert!(is_version_newer("1.0.1", "1.0.0"));
        assert!(is_version_newer("1.1.0", "1.0.0"));
        assert!(is_version_newer("2.0.0", "1.9.9"));
        assert!(!is_version_newer("1.0.0", "1.0.0"));
        assert!(!is_version_newer("1.0.0", "1.0.1"));
        assert!(is_version_newer("1.0.1", "1.0"));
        assert!(!is_version_newer("1.0.0", "1.0"));
        assert!(!is_version_newer("1.0", "1.0.0"));
        assert!(!is_version_newer("1.0.0.0", "1.0.0"));
    }
}
