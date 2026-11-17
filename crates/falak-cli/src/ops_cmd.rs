//! `falak breakglass`: emergency access to an app, through Office (T6.4).
//!
//!   request   ask for access: needs a reason and a duration; raises an alert at once.
//!             Tier 1 and 2 apps: you can claim straight away.
//!             Tier 3 apps: a second administrator must approve first.
//!   approve   a different administrator approves a pending request.
//!   claim     the requester collects the short-lived token (printed once).
//!   list      recent requests and their state.
//!
//! The password is read from the environment variable named by `--password-env`, never
//! from an argument, so it does not land in shell history.

use serde_json::{Value, json};

use crate::args::{Command, Extra};

/// An agent for Office: ten seconds, and a refusal is an answer to read (it carries a
/// problem document), not an error.
pub(crate) fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// The JSON of a successful answer. Office answers errors with a problem document; show
/// its detail, not the status line.
pub(crate) fn json_of(
    res: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<Value, String> {
    let mut res = res.map_err(|e| format!("cannot reach Office: {e}"))?;
    let code = res.status().as_u16();
    if res.status().is_success() {
        return res.body_mut().read_json().map_err(|e| e.to_string());
    }
    let body: Value = res.body_mut().read_json().unwrap_or(Value::Null);
    let detail = body["detail"]
        .as_str()
        .or_else(|| body["title"].as_str())
        .unwrap_or("refused");
    Err(format!("Office refused ({code}): {detail}"))
}

fn session(agent: &ureq::Agent, base: &str, extra: &Extra) -> Result<String, String> {
    let email = extra.email.as_deref().ok_or("`--email` is required")?;
    let var = extra
        .password_env
        .as_deref()
        .ok_or("`--password-env <VAR>` is required: the name of a variable holding the password")?;
    let password = std::env::var(var).map_err(|_| format!("`{var}` is not set"))?;
    let login: Value = json_of(
        agent
            .post(&format!("{base}/v1/auth/login"))
            .send_json(json!({"email": email, "password": password})),
    )
    .map_err(|e| format!("sign-in to Office failed: {e}"))?;
    login["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "Office gave no session token".to_owned())
}

pub fn breakglass(command: Command, extra: &Extra) -> Result<u8, String> {
    let office = extra
        .office
        .as_deref()
        .ok_or("`--office <url>` is required")?;
    let base = crate::office_cmd::secure_base(office)?;
    let base = base.as_str();
    let agent = agent();
    let token = session(&agent, base, extra)?;
    let auth = format!("Bearer {token}");
    let need_id = || {
        let id = extra
            .id
            .as_deref()
            .ok_or_else(|| "`--id <request id>` is required".to_owned())?;
        crate::office_cmd::path_segment(id, "request id")
    };
    let out: Value = match command {
        Command::BreakGlassRequest => {
            let app = extra.app.as_deref().ok_or("`--app <name>` is required")?;
            let reason = extra
                .reason
                .as_deref()
                .ok_or("`--reason <text>` is required: it goes in the audit log and the alert")?;
            let mut body = json!({"app": app, "reason": reason});
            if let Some(m) = extra.minutes {
                body["minutes"] = json!(m);
            }
            if let Some(t) = extra.tier {
                body["tier"] = json!(t);
            }
            json_of(
                agent
                    .post(&format!("{base}/v1/_office/breakglass"))
                    .header("authorization", &auth)
                    .send_json(body),
            )?
        }
        Command::BreakGlassApprove => json_of(
            agent
                .post(&format!(
                    "{base}/v1/_office/breakglass/{}/approve",
                    need_id()?
                ))
                .header("authorization", &auth)
                .send(""),
        )?,
        Command::BreakGlassClaim => json_of(
            agent
                .post(&format!(
                    "{base}/v1/_office/breakglass/{}/claim",
                    need_id()?
                ))
                .header("authorization", &auth)
                .send(""),
        )?,
        _ => json_of(
            agent
                .get(&format!("{base}/v1/_office/breakglass"))
                .header("authorization", &auth)
                .call(),
        )?,
    };
    println!("{out}");
    if command == Command::BreakGlassRequest && out["needs_second_approver"] == json!(true) {
        eprintln!(
            "Tier 3: a different administrator must run `falak breakglass approve --id {}` before you can claim.",
            out["id"].as_str().unwrap_or("?")
        );
    }
    Ok(0)
}

/// `falak office rotate-credential`: cut off a compromised app key and print the one-time
/// token the real app uses to enroll again (`falak office enroll --token ...`).
pub fn rotate_credential(extra: &Extra) -> Result<u8, String> {
    let office = extra
        .office
        .as_deref()
        .ok_or("`--office <url>` is required")?;
    let app = extra.app.as_deref().ok_or("`--app <name>` is required")?;
    let app = crate::office_cmd::path_segment(app, "app name")?;
    let base = crate::office_cmd::secure_base(office)?;
    let base = base.as_str();
    let agent = agent();
    let token = session(&agent, base, extra)?;
    let out: Value = json_of(
        agent
            .post(&format!("{base}/v1/_office/apps/{app}/rotate-credential"))
            .header("authorization", format!("Bearer {token}"))
            .send(""),
    )?;
    println!("{out}");
    eprintln!(
        "The old credential is revoked. Enroll the app again within 15 minutes: delete its .falak/office.json and .falak/office-app-key.json, then `falak office enroll --office {base} --token-env <VAR>` with the enrollment_token in that variable."
    );
    Ok(0)
}
