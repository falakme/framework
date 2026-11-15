//! Behaviour of local identity, run against the in-memory store and a real SQLite file.

use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

use falak_auth::{
    identity::{LocalIdentity, Policy, Tokens},
    keys::LocalKeys,
    store::{AuthStore, MemoryStore, Placeholders, SqlStore},
    token::TokenConfig,
};
use falak_contracts::{
    ErrorKind,
    identity::IdentityProvider,
    support::{Clock, IdGenerator},
};
use falak_driver_sqlite::SqliteDriver;

#[derive(Clone)]
struct SharedClock(Arc<AtomicI64>);
impl Clock for SharedClock {
    fn now_micros(&self) -> i64 {
        self.0.load(Ordering::Relaxed) * 1_000_000
    }
}

type Clk = Arc<AtomicI64>;
type Fixture<S> = (LocalIdentity<S, SharedClock, Counter>, Clk);

struct Counter(AtomicU64);
impl IdGenerator for Counter {
    fn new_id(&self) -> [u8; 16] {
        let n = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        let mut b = [0u8; 16];
        b[8..].copy_from_slice(&n.to_be_bytes());
        b
    }
}

const PW: &str = "correct horse battery";
const T0: i64 = 1_800_000_000;

fn identity<S: AuthStore>(store: S) -> Fixture<S> {
    let clock: Clk = Arc::new(AtomicI64::new(T0));
    let id = LocalIdentity::new(
        store,
        LocalKeys::generate(),
        TokenConfig {
            issuer: "falak-local".into(),
            audience: "notebook".into(),
            leeway_secs: 0,
        },
        Policy::default(),
        SharedClock(clock.clone()),
        Counter(AtomicU64::new(0)),
    );
    (id, clock)
}

async fn signup_login_and_verify<S: AuthStore>((id, clock): Fixture<S>) {
    let user = id.signup("  Ann@Example.com ", PW).await.unwrap();
    id.set_roles(&user, &["admin".to_string()]).await.unwrap();
    let t = id.login("ann@example.com", PW).await.unwrap();
    assert_eq!(t.expires_in, 900);
    let p = id.verify(&t.access_token).await.unwrap();
    assert_eq!(p.subject, user);
    assert_eq!(p.roles, ["admin"]);
    // The subject is a lowercase hyphenated UUID, as an `owner` field stores it.
    assert_eq!(user.len(), 36);
    assert_eq!(user.matches('-').count(), 4);
    // Access tokens expire.
    clock.fetch_add(901, Ordering::Relaxed);
    assert!(id.verify(&t.access_token).await.is_err());
}

async fn wrong_password_and_unknown_email_look_the_same<S: AuthStore>((id, _clock): Fixture<S>) {
    id.signup("a@example.com", PW).await.unwrap();
    let wrong = id
        .login("a@example.com", "not the password")
        .await
        .unwrap_err();
    let unknown = id.login("nobody@example.com", PW).await.unwrap_err();
    let malformed = id.login("not an email", PW).await.unwrap_err();
    for e in [&wrong, &unknown, &malformed] {
        assert_eq!(e.kind(), ErrorKind::Unauthenticated);
        assert_eq!(e.code(), "invalid_credentials");
    }
    assert_eq!(wrong.to_string(), unknown.to_string());
}

async fn lockout_blocks_even_the_right_password_until_the_window_passes<S: AuthStore>(
    (id, clock): Fixture<S>,
) {
    id.signup("a@example.com", PW).await.unwrap();
    for _ in 0..5 {
        let e = id
            .login("a@example.com", "wrong wrong wrong")
            .await
            .unwrap_err();
        assert_eq!(e.code(), "invalid_credentials");
    }
    let e = id.login("a@example.com", PW).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RateLimited);
    assert!(e.kind().retryable());
    // Another email is unaffected.
    id.signup("b@example.com", PW).await.unwrap();
    assert!(id.login("b@example.com", PW).await.is_ok());
    // After the window the right password works, and success clears the count.
    clock.fetch_add(15 * 60 + 1, Ordering::Relaxed);
    assert!(id.login("a@example.com", PW).await.is_ok());
    for _ in 0..4 {
        id.login("a@example.com", "wrong wrong wrong")
            .await
            .unwrap_err();
    }
    assert!(id.login("a@example.com", PW).await.is_ok());
}

async fn refresh_rotates_and_reuse_ends_every_session<S: AuthStore>((id, _clock): Fixture<S>) {
    id.signup("a@example.com", PW).await.unwrap();
    let first = id.login("a@example.com", PW).await.unwrap();
    let other_device = id.login("a@example.com", PW).await.unwrap();
    let second = id.refresh(&first.refresh_token).await.unwrap();
    assert_ne!(first.refresh_token, second.refresh_token);
    id.verify(&second.access_token).await.unwrap();

    // The old token is dead, and using it again ends every session, on every device.
    assert!(id.refresh(&first.refresh_token).await.is_err());
    assert!(id.refresh(&second.refresh_token).await.is_err());
    assert!(id.refresh(&other_device.refresh_token).await.is_err());
    // A fresh login still works.
    assert!(id.login("a@example.com", PW).await.is_ok());
}

async fn logout_ends_the_session<S: AuthStore>((id, clock): Fixture<S>) {
    id.signup("a@example.com", PW).await.unwrap();
    let t: Tokens = id.login("a@example.com", PW).await.unwrap();
    id.logout(&t.refresh_token).await.unwrap();
    assert!(id.refresh(&t.refresh_token).await.is_err());
    id.logout("never-issued").await.unwrap();
    // Sessions expire on their own.
    let t = id.login("a@example.com", PW).await.unwrap();
    clock.fetch_add(30 * 24 * 3600 + 1, Ordering::Relaxed);
    assert!(id.refresh(&t.refresh_token).await.is_err());
}

async fn reset_is_single_use_and_ends_sessions<S: AuthStore>((id, clock): Fixture<S>) {
    id.signup("a@example.com", PW).await.unwrap();
    let session = id.login("a@example.com", PW).await.unwrap();
    assert!(
        id.request_reset("nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );

    let token = id.request_reset("A@example.com").await.unwrap().unwrap();
    let new_pw = "a brand new passphrase";
    assert!(
        id.reset_password(&token, "short").await.is_err(),
        "weak password"
    );
    id.reset_password(&token, new_pw).await.unwrap();

    let again = id
        .reset_password(&token, "another passphrase here")
        .await
        .unwrap_err();
    assert_eq!(again.code(), "invalid_reset_token", "second use fails");
    assert!(
        id.refresh(&session.refresh_token).await.is_err(),
        "sessions ended"
    );
    assert!(
        id.login("a@example.com", PW).await.is_err(),
        "old password dead"
    );
    assert!(id.login("a@example.com", new_pw).await.is_ok());

    // An expired token fails.
    let token = id.request_reset("a@example.com").await.unwrap().unwrap();
    clock.fetch_add(3601, Ordering::Relaxed);
    assert!(
        id.reset_password(&token, "yet another passphrase")
            .await
            .is_err()
    );
    // A made-up token fails the same way.
    let e = id
        .reset_password("00", "yet another passphrase")
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_reset_token");
}

async fn duplicate_email_and_bad_input<S: AuthStore>((id, _clock): Fixture<S>) {
    id.signup("a@example.com", PW).await.unwrap();
    let e = id.signup("A@EXAMPLE.COM", PW).await.unwrap_err();
    assert_eq!(e.code(), "email_taken");
    assert_eq!(e.kind(), ErrorKind::Conflict);
    for bad in [
        "",
        "plain",
        "a@b",
        "@example.com",
        "a b@example.com",
        "a@@example.com",
    ] {
        assert_eq!(
            id.signup(bad, PW).await.unwrap_err().code(),
            "invalid_email",
            "{bad}"
        );
    }
    assert_eq!(
        id.signup("c@example.com", "short")
            .await
            .unwrap_err()
            .code(),
        "weak_password"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn memory_store() {
    signup_login_and_verify(identity(MemoryStore::new())).await;
    wrong_password_and_unknown_email_look_the_same(identity(MemoryStore::new())).await;
    lockout_blocks_even_the_right_password_until_the_window_passes(identity(MemoryStore::new()))
        .await;
    refresh_rotates_and_reuse_ends_every_session(identity(MemoryStore::new())).await;
    logout_ends_the_session(identity(MemoryStore::new())).await;
    reset_is_single_use_and_ends_sessions(identity(MemoryStore::new())).await;
    duplicate_email_and_bad_input(identity(MemoryStore::new())).await;
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_store() {
    let make = || async {
        let driver = SqliteDriver::in_memory().await.unwrap();
        let store = SqlStore::new(driver, Placeholders::Question);
        store.migrate().await.unwrap();
        store
    };
    // Each scenario gets its own empty database.
    signup_login_and_verify(identity(make().await)).await;
    wrong_password_and_unknown_email_look_the_same(identity(make().await)).await;
    lockout_blocks_even_the_right_password_until_the_window_passes(identity(make().await)).await;
    refresh_rotates_and_reuse_ends_every_session(identity(make().await)).await;
    logout_ends_the_session(identity(make().await)).await;
    reset_is_single_use_and_ends_sessions(identity(make().await)).await;
    duplicate_email_and_bad_input(identity(make().await)).await;
}

#[tokio::test(flavor = "current_thread")]
async fn migrate_twice_is_harmless() {
    let driver = SqliteDriver::in_memory().await.unwrap();
    let store = SqlStore::new(driver, Placeholders::Question);
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
}
