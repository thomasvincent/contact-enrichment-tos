// In-memory ContactRepository for dev/testing
use super::repository::{ContactRepository, RepositoryError, SecurityContext};
use crate::domain::contact::Contact;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Default, Clone)]
pub struct MemContactRepository {
    // Human note: dev-only store; not persistent and not concurrent-safe for high write rates
    store: Arc<RwLock<HashMap<Uuid, Contact>>>,
}

impl MemContactRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ContactRepository for MemContactRepository {
    async fn find_by_id(
        &self,
        id: Uuid,
        _security_context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError> {
        let map = self.store.read().unwrap();
        Ok(map.get(&id).cloned())
    }

    async fn find_by_email_hash(
        &self,
        email_hash: &[u8],
        _security_context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError> {
        let map = self.store.read().unwrap();
        Ok(map
            .values()
            .find(|c| c.canonical_email_hash.as_slice() == email_hash)
            .cloned())
    }

    async fn save(
        &self,
        contact: &Contact,
        _security_context: &SecurityContext,
    ) -> Result<(), RepositoryError> {
        let mut map = self.store.write().unwrap();
        map.insert(contact.id, contact.clone());
        Ok(())
    }

    async fn delete(
        &self,
        id: Uuid,
        _security_context: &SecurityContext,
    ) -> Result<(), RepositoryError> {
        let mut map = self.store.write().unwrap();
        map.remove(&id);
        Ok(())
    }

    async fn exists_by_email_hash(
        &self,
        email_hash: &[u8],
        _security_context: &SecurityContext,
    ) -> Result<bool, RepositoryError> {
        let map = self.store.read().unwrap();
        Ok(map
            .values()
            .any(|c| c.canonical_email_hash.as_slice() == email_hash))
    }
}