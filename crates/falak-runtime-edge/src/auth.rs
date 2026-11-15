//! Sign-up and login on the edge: the local identity service over D1.

use std::{future::Future, pin::Pin};

use falak_auth::{
    identity::{LocalIdentity, Tokens},
    store::SqlStore,
    system::{RandomIds, SystemClock},
};
use falak_contracts::Result;
use falak_runtime_native::auth_routes::AuthService;
use worker::send::{SendFuture, SendWrapper};

use crate::driver::EdgeDriver;

pub type Identity = LocalIdentity<SqlStore<EdgeDriver>, SystemClock, RandomIds>;

type Boxed<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub struct EdgeAuth(pub SendWrapper<Identity>);

impl AuthService for EdgeAuth {
    fn signup<'a>(&'a self, email: &'a str, password: &'a str) -> Boxed<'a, String> {
        Box::pin(SendFuture::new(self.0.signup(email, password)))
    }
    fn login<'a>(&'a self, email: &'a str, password: &'a str) -> Boxed<'a, Tokens> {
        Box::pin(SendFuture::new(self.0.login(email, password)))
    }
    fn refresh<'a>(&'a self, refresh_token: &'a str) -> Boxed<'a, Tokens> {
        Box::pin(SendFuture::new(self.0.refresh(refresh_token)))
    }
    fn logout<'a>(&'a self, refresh_token: &'a str) -> Boxed<'a, ()> {
        Box::pin(SendFuture::new(self.0.logout(refresh_token)))
    }
    fn request_reset<'a>(&'a self, email: &'a str) -> Boxed<'a, Option<String>> {
        Box::pin(SendFuture::new(self.0.request_reset(email)))
    }
    fn reset_password<'a>(&'a self, token: &'a str, new_password: &'a str) -> Boxed<'a, ()> {
        Box::pin(SendFuture::new(self.0.reset_password(token, new_password)))
    }
    fn jwks(&self) -> serde_json::Value {
        self.0.verifier().jwks()
    }
}
