use crate::types::{DecisionRecord, GamePolicy, SessionRecord};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Default)]
struct Memory {
    sessions: HashMap<String, SessionRecord>,
    decisions: HashMap<String, DecisionRecord>,
    policies: HashMap<String, GamePolicy>,
    evidence: HashMap<String, Value>,
}

pub struct Store {
    data_dir: PathBuf,
    inner: RwLock<Memory>,
}

impl Store {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(data_dir.join("sessions"))?;
        fs::create_dir_all(data_dir.join("decisions"))?;
        fs::create_dir_all(data_dir.join("policies"))?;
        fs::create_dir_all(data_dir.join("evidence"))?;

        let store = Self {
            data_dir,
            inner: RwLock::new(Memory::default()),
        };
        store.load_all()?;
        Ok(store)
    }

    fn load_all(&self) -> Result<(), StoreError> {
        let mut memory = self.inner.write().expect("store lock");

        for entry in fs::read_dir(self.data_dir.join("sessions"))? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let session: SessionRecord = serde_json::from_slice(&fs::read(entry.path())?)?;
            memory
                .sessions
                .insert(session.session_id.clone(), session);
        }

        for entry in fs::read_dir(self.data_dir.join("decisions"))? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let decision: DecisionRecord = serde_json::from_slice(&fs::read(entry.path())?)?;
            memory
                .decisions
                .insert(decision.session_id.clone(), decision);
        }

        for entry in fs::read_dir(self.data_dir.join("policies"))? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let policy: GamePolicy = serde_json::from_slice(&fs::read(entry.path())?)?;
            memory.policies.insert(policy.game_id.clone(), policy);
        }

        Ok(())
    }

    fn write_json<T: serde::Serialize>(
        &self,
        folder: &str,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let path = self.data_dir.join(folder).join(format!("{key}.json"));
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn put_session(&self, session: &SessionRecord) -> Result<(), StoreError> {
        self.write_json("sessions", &session.session_id, session)?;
        self.inner
            .write()
            .expect("store lock")
            .sessions
            .insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionRecord> {
        self.inner
            .read()
            .expect("store lock")
            .sessions
            .get(session_id)
            .cloned()
    }

    pub fn put_decision(&self, decision: &DecisionRecord) -> Result<(), StoreError> {
        self.write_json("decisions", &decision.session_id, decision)?;
        self.inner
            .write()
            .expect("store lock")
            .decisions
            .insert(decision.session_id.clone(), decision.clone());
        Ok(())
    }

    pub fn get_decision(&self, session_id: &str) -> Option<DecisionRecord> {
        self.inner
            .read()
            .expect("store lock")
            .decisions
            .get(session_id)
            .cloned()
    }

    pub fn put_policy(&self, policy: &GamePolicy) -> Result<(), StoreError> {
        self.write_json("policies", &policy.game_id, policy)?;
        self.inner
            .write()
            .expect("store lock")
            .policies
            .insert(policy.game_id.clone(), policy.clone());
        Ok(())
    }

    pub fn get_policy(&self, game_id: &str) -> Option<GamePolicy> {
        self.inner
            .read()
            .expect("store lock")
            .policies
            .get(game_id)
            .cloned()
    }

    pub fn put_evidence(&self, key: &str, value: &Value) -> Result<(), StoreError> {
        self.write_json("evidence", key, value)?;
        self.inner
            .write()
            .expect("store lock")
            .evidence
            .insert(key.to_string(), value.clone());
        Ok(())
    }
}
