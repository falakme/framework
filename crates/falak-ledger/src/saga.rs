//! Compensating sagas over federated commands (T8.5).
//!
//! A checkout touches two apps: Horizon holds and moves the money, a storefront (any app, for example
//! GardenX) records the order. There is no distributed transaction. The saga runs the
//! steps in order, and when one fails it runs the **compensation** of every step that
//! already succeeded, newest first:
//!
//! ```text
//! reserve funds (Horizon)      undo: release the hold
//! place the order (storefront) undo: cancel the order
//! capture funds (Horizon)      last step: nothing after it to undo
//! ```
//!
//! Every call carries an idempotency key derived from the saga id and step, so a retry
//! of a step, or of a compensation, never does the work twice.
//!
//! The runner is written against [`Participant`], a trait, because the events that will
//! drive and persist sagas arrive with Phase 5. Until then a saga that is interrupted by
//! a crash is not resumed: the caller re-runs it with the same id (every call is
//! idempotent, so this is safe) and a [`Outcome::Stuck`] result lists what to retry.

use falak_contracts::Error;
use serde_json::{Value, json};

use crate::{Command, Currency, Ledger};

/// One federated command call and, optionally, the call that undoes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub app: String,
    pub command: String,
    pub args: Value,
    pub compensation: Option<(String, Value)>,
}

/// How a saga ended.
#[derive(Debug)]
pub enum Outcome {
    /// Every step ran.
    Completed,
    /// A step failed and every earlier step was undone.
    Compensated { failed_step: usize, error: Error },
    /// A step failed and some compensations also failed. Retry `uncompensated`
    /// (step indexes) by running the saga again with the same id.
    Stuck {
        failed_step: usize,
        error: Error,
        uncompensated: Vec<usize>,
    },
}

/// Something that can run a command in an app.
pub trait Participant {
    /// Run `command` in `app`. Must be idempotent for a given `key`.
    async fn call(&self, app: &str, command: &str, key: &str, args: &Value)
    -> Result<Value, Error>;
}

/// Run the steps. `compensation_attempts` bounds the retries of each compensation.
pub async fn run<P: Participant>(
    saga_id: &str,
    steps: &[Step],
    participant: &P,
    compensation_attempts: u32,
) -> Outcome {
    for (i, step) in steps.iter().enumerate() {
        let key = format!("{saga_id}/{i}/do");
        let Err(error) = participant
            .call(&step.app, &step.command, &key, &step.args)
            .await
        else {
            continue;
        };
        let mut uncompensated = Vec::new();
        for (j, done) in steps[..i].iter().enumerate().rev() {
            let Some((command, args)) = &done.compensation else {
                continue;
            };
            let key = format!("{saga_id}/{j}/undo");
            let mut ok = false;
            for _ in 0..compensation_attempts.max(1) {
                if participant
                    .call(&done.app, command, &key, args)
                    .await
                    .is_ok()
                {
                    ok = true;
                    break;
                }
            }
            if !ok {
                uncompensated.push(j);
            }
        }
        return if uncompensated.is_empty() {
            Outcome::Compensated {
                failed_step: i,
                error,
            }
        } else {
            Outcome::Stuck {
                failed_step: i,
                error,
                uncompensated,
            }
        };
    }
    Outcome::Completed
}

/// The money half of a checkout: Horizon's federated commands, run on the ledger.
/// `args` is the ledger [`Command`] as JSON (`{"type": "reserve", ...}`); the command
/// name must match its type, so a step cannot be redirected by editing one field.
pub struct HorizonParticipant {
    pub ledger: Ledger,
}

impl Participant for HorizonParticipant {
    async fn call(
        &self,
        app: &str,
        command: &str,
        key: &str,
        args: &Value,
    ) -> Result<Value, Error> {
        if app != "horizon" {
            return Err(Error::unsupported(
                "saga_unknown_app",
                "This participant only runs Horizon commands.",
            ));
        }
        let cmd: Command = serde_json::from_value(args.clone()).map_err(|_| {
            Error::invalid_input("saga_bad_args", "The arguments are not a ledger command.")
        })?;
        if cmd.kind() != command {
            return Err(Error::invalid_input(
                "saga_command_mismatch",
                "The command name does not match its arguments.",
            ));
        }
        let posted = self.ledger.execute(key, &cmd).await?;
        Ok(json!({ "tx_id": posted.tx_id, "replayed": posted.replayed }))
    }
}

/// Routes `horizon` to the ledger and every other app to `storefront`.
pub struct Router<S> {
    pub horizon: HorizonParticipant,
    pub storefront: S,
}

impl<S: Participant> Participant for Router<S> {
    async fn call(
        &self,
        app: &str,
        command: &str,
        key: &str,
        args: &Value,
    ) -> Result<Value, Error> {
        if app == "horizon" {
            self.horizon.call(app, command, key, args).await
        } else {
            self.storefront.call(app, command, key, args).await
        }
    }
}

/// The checkout saga for a storefront: reserve, place the order, capture.
#[allow(clippy::too_many_arguments)]
pub fn checkout(
    storefront_app: &str,
    place_command: &str,
    place_args: Value,
    cancel_command: &str,
    cancel_args: Value,
    hold: &str,
    buyer_account: &str,
    merchant_account: &str,
    amount: i64,
    currency: Currency,
) -> Vec<Step> {
    let json_of = |c: &Command| serde_json::to_value(c).unwrap_or(Value::Null);
    vec![
        Step {
            app: "horizon".into(),
            command: "reserve".into(),
            args: json_of(&Command::Reserve {
                hold: hold.into(),
                account: buyer_account.into(),
                amount,
                currency,
            }),
            compensation: Some((
                "release".into(),
                json_of(&Command::Release { hold: hold.into() }),
            )),
        },
        Step {
            app: storefront_app.into(),
            command: place_command.into(),
            args: place_args,
            compensation: Some((cancel_command.into(), cancel_args)),
        },
        Step {
            app: "horizon".into(),
            command: "capture".into(),
            args: json_of(&Command::Capture {
                hold: hold.into(),
                to: merchant_account.into(),
                amount,
            }),
            compensation: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Records every call; fails the calls named in `fail`.
    struct Stub {
        calls: Mutex<Vec<String>>,
        fail: Vec<&'static str>,
    }

    impl Participant for Stub {
        async fn call(
            &self,
            app: &str,
            command: &str,
            key: &str,
            _args: &Value,
        ) -> Result<Value, Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{app}.{command} {key}"));
            if self.fail.contains(&command) {
                return Err(Error::new(
                    falak_contracts::ErrorKind::Unavailable,
                    "down",
                    "down",
                ));
            }
            Ok(Value::Null)
        }
    }

    fn steps() -> Vec<Step> {
        checkout(
            "shop",
            "item.create",
            json!({ "id": "e1" }),
            "item.delete",
            json!({ "id": "e1" }),
            "hold-1",
            "buyer",
            "school",
            500,
            Currency::new("USD").unwrap(),
        )
    }

    #[tokio::test]
    async fn success_runs_every_step_once() {
        let stub = Stub {
            calls: Mutex::default(),
            fail: vec![],
        };
        assert!(matches!(
            run("saga-1", &steps(), &stub, 3).await,
            Outcome::Completed
        ));
        let calls = stub.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            [
                "horizon.reserve saga-1/0/do",
                "academy.enrollment.create saga-1/1/do",
                "horizon.capture saga-1/2/do"
            ]
        );
    }

    #[tokio::test]
    async fn a_failed_order_releases_the_hold() {
        let stub = Stub {
            calls: Mutex::default(),
            fail: vec!["enrollment.create"],
        };
        let out = run("saga-2", &steps(), &stub, 3).await;
        assert!(matches!(out, Outcome::Compensated { failed_step: 1, .. }));
        let calls = stub.calls.lock().unwrap().clone();
        assert_eq!(calls.last().unwrap(), "horizon.release saga-2/0/undo");
        assert!(!calls.iter().any(|c| c.contains("capture")));
    }

    #[tokio::test]
    async fn a_failed_capture_undoes_the_order_then_the_hold() {
        let stub = Stub {
            calls: Mutex::default(),
            fail: vec!["capture"],
        };
        let out = run("saga-3", &steps(), &stub, 3).await;
        assert!(matches!(out, Outcome::Compensated { failed_step: 2, .. }));
        let calls = stub.calls.lock().unwrap().clone();
        let undo: Vec<_> = calls.iter().filter(|c| c.contains("undo")).collect();
        assert_eq!(
            undo,
            [
                "academy.enrollment.delete saga-3/1/undo",
                "horizon.release saga-3/0/undo"
            ]
        );
    }

    #[tokio::test]
    async fn a_compensation_that_keeps_failing_is_reported_stuck() {
        let stub = Stub {
            calls: Mutex::default(),
            fail: vec!["enrollment.create", "release"],
        };
        match run("saga-4", &steps(), &stub, 2).await {
            Outcome::Stuck { uncompensated, .. } => assert_eq!(uncompensated, vec![0]),
            other => panic!("{other:?}"),
        }
        let undo_calls = stub
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.contains("release"))
            .count();
        assert_eq!(undo_calls, 2);
    }
}
