//! Accounts, behind a small trait so Office does not care which database holds them.

use std::{future::Future, pin::Pin, sync::Arc};

use falak_auth::{
    identity::LocalIdentity,
    store::{AuthStore, Placeholders, SqlStore},
    system::{RandomIds, SystemClock},
};
use falak_contracts::Result;
use falak_driver_postgres::PostgresDriver;
use falak_driver_sqlite::SqliteDriver;
use falak_runtime_native::auth_routes::AuthService;

type Boxed<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// What Office needs to manage accounts.
pub trait Users: Send + Sync + 'static {
    /// Make the account tables.
    fn migrate(&self) -> Boxed<'_, ()>;
    /// Make an account with these roles. Returns its id.
    fn create<'a>(
        &'a self,
        email: &'a str,
        password: &'a str,
        roles: &'a [String],
    ) -> Boxed<'a, String>;
    /// The id of the account with this email, if any.
    fn find<'a>(&'a self, email: &'a str) -> Boxed<'a, Option<String>>;
}

pub struct Accounts<I, S> {
    identity: Arc<I>,
    store: S,
}

macro_rules! accounts {
    ($name:ident, $driver:ty, $placeholders:expr) => {
        /// The sign-in service (for `/v1/auth/*`) and the account manager, over one
        /// database.
        pub fn $name(
            driver: $driver,
            keys: falak_auth::keys::LocalKeys,
            config: falak_auth::token::TokenConfig,
        ) -> (Arc<dyn AuthService>, Arc<dyn Users>) {
            let store = SqlStore::new(driver.clone(), $placeholders);
            let identity = Arc::new(LocalIdentity::new(
                SqlStore::new(driver, $placeholders),
                keys,
                config,
                falak_auth::identity::Policy::default(),
                SystemClock,
                RandomIds,
            ));
            (
                identity.clone() as Arc<dyn AuthService>,
                Arc::new(Accounts { identity, store }) as Arc<dyn Users>,
            )
        }

        impl Users
            for Accounts<
                LocalIdentity<SqlStore<$driver>, SystemClock, RandomIds>,
                SqlStore<$driver>,
            >
        {
            fn migrate(&self) -> Boxed<'_, ()> {
                Box::pin(async move { self.store.migrate().await })
            }

            fn create<'a>(
                &'a self,
                email: &'a str,
                password: &'a str,
                roles: &'a [String],
            ) -> Boxed<'a, String> {
                Box::pin(async move {
                    let id = self.identity.signup(email, password).await?;
                    self.identity.set_roles(&id, roles).await?;
                    Ok(id)
                })
            }

            fn find<'a>(&'a self, email: &'a str) -> Boxed<'a, Option<String>> {
                Box::pin(async move {
                    let email = email.trim().to_lowercase();
                    Ok(self.store.user_by_email(&email).await?.map(|u| u.id))
                })
            }
        }
    };
}

accounts!(open_sqlite, SqliteDriver, Placeholders::Question);
accounts!(open_postgres, PostgresDriver, Placeholders::Numbered);
