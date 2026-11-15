//! Compile check: every contract trait can be implemented. Mirrors what each owner's
//! crate does with its stub before the real implementation lands.

use falak_contracts::{
    Error, Result,
    admin::{AdminEntity, AdminProvider},
    capability::{self, CapabilityProfile},
    driver::*,
    events::{Event, EventPublisher},
    identity::*,
    jobs::{Job, JobDispatcher, Lease},
    keys::*,
    objects::{ObjectStore, PresignRequest, Presigned},
    support::{Clock, IdGenerator},
    telemetry::{LogRecord, TelemetryExporter},
};

struct Stub;
struct StubTx;

impl Transaction for StubTx {
    async fn query(&mut self, _: Statement) -> Result<Rows> {
        Ok(Rows::default())
    }
    async fn execute(&mut self, _: Statement) -> Result<Outcome> {
        Ok(Outcome::default())
    }
    async fn commit(self) -> Result<()> {
        Ok(())
    }
    async fn rollback(self) -> Result<()> {
        Ok(())
    }
}

impl StorageDriver for Stub {
    type Tx = StubTx;
    fn profile(&self) -> &CapabilityProfile {
        &capability::SQLITE
    }
    async fn query(&self, _: &RequestContext, _: Statement) -> Result<Rows> {
        Ok(Rows::default())
    }
    async fn batch(&self, _: &RequestContext, s: Vec<Statement>) -> Result<Vec<Outcome>> {
        Ok(vec![Outcome::default(); s.len()])
    }
    async fn begin(&self, _: &RequestContext, _: TxOptions) -> Result<StubTx> {
        Ok(StubTx)
    }
}

impl IdentityProvider for Stub {
    async fn verify(&self, _: &str) -> Result<Principal> {
        Err(Error::unauthenticated())
    }
}

impl SigningKeyProvider for Stub {
    fn active_key_id(&self) -> KeyId {
        KeyId("k1".into())
    }
    async fn sign(&self, _: &KeyId, _: &[u8]) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    async fn verify(&self, _: &KeyId, _: &[u8], _: &[u8]) -> Result<bool> {
        Ok(false)
    }
    async fn public_keys(&self) -> Result<Vec<PublicKey>> {
        Ok(vec![])
    }
}

impl EncryptionKeyProvider for Stub {
    async fn generate_data_key(&self, _: &str) -> Result<DataKey> {
        Err(Error::unsupported("stub", "stub"))
    }
    async fn unwrap_data_key(&self, _: &str, _: &[u8]) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}

impl EventPublisher for Stub {
    async fn publish(&self, _: Vec<Event>) -> Result<()> {
        Ok(())
    }
}

impl JobDispatcher for Stub {
    async fn enqueue(&self, _: Job) -> Result<()> {
        Ok(())
    }
    async fn lease(&self, _: &[String], _: usize, _: u64) -> Result<Vec<Lease>> {
        Ok(vec![])
    }
    async fn heartbeat(&self, _: &str, _: u64) -> Result<()> {
        Ok(())
    }
    async fn complete(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn fail(&self, _: &str, _: bool, _: &str) -> Result<()> {
        Ok(())
    }
}

impl TelemetryExporter for Stub {
    fn log(&self, _: LogRecord) {}
    fn metric(&self, _: &str, _: f64, _: &[(&str, &str)]) {}
}

impl AdminProvider for Stub {
    async fn entities(&self, _: &Principal) -> Result<Vec<AdminEntity>> {
        Ok(vec![])
    }
}

impl ObjectStore for Stub {
    async fn presign_upload(&self, _: PresignRequest) -> Result<Presigned> {
        Err(Error::unsupported("stub", "stub"))
    }
    async fn presign_download(&self, _: PresignRequest) -> Result<Presigned> {
        Err(Error::unsupported("stub", "stub"))
    }
}

impl Clock for Stub {
    fn now_micros(&self) -> i64 {
        0
    }
}

impl IdGenerator for Stub {
    fn new_id(&self) -> [u8; 16] {
        [0; 16]
    }
}

#[test]
fn stubs_compile_and_report_profile() {
    assert_eq!(Stub.profile().name, "sqlite");
    assert_eq!(Stub.new_id(), [0; 16]);
}
