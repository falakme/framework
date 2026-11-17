use std::sync::atomic::{AtomicBool, Ordering};

use falak_contracts::ir::IrJob;
use falak_worker::runner::{
    ProcessRunner, RunError, RunRequest, Runner, container_args, verify_requirements,
};
use serde_json::json;

fn spec(command: &[&str]) -> IrJob {
    IrJob {
        name: "scan".into(),
        input: vec![],
        image: "registry.example.com/scan:1".into(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
        timeout_seconds: 5,
        max_attempts: 3,
        memory_mb: 256,
        cpus: 2,
        egress: vec![],
        requirements_sha256: None,
    }
}

fn request<'a>(spec: &'a IrJob, payload: &'a str) -> RunRequest<'a> {
    RunRequest {
        job_id: "abc",
        kind: "scan",
        payload,
        spec,
        credential: "jt_x",
        office_url: "https://office.example",
        egress_socket: None,
    }
}

#[test]
fn a_container_is_non_root_read_only_limited_and_has_no_network() {
    let s = spec(&["python", "main.py"]);
    let args = container_args(&request(&s, "{}"), "falak-job-abc", None).join(" ");
    for want in [
        "--user 65534:65534",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--network none",
        "--memory 256m",
        "--memory-swap 256m",
        "--cpus 2",
        "--pids-limit 256",
    ] {
        assert!(args.contains(want), "missing `{want}` in {args}");
    }
    assert!(args.ends_with("registry.example.com/scan:1 python main.py"));
    assert!(!args.contains("--privileged"));
    // The credential travels in the engine's environment, not on its command line.
    assert!(!args.contains("jt_x"), "{args}");
    assert!(args.contains("-e FALAK_JOB_TOKEN"));
}

#[test]
fn an_image_or_id_that_would_be_read_as_an_engine_option_is_refused() {
    use falak_worker::runner::validate;
    let mut s = spec(&["x"]);
    assert!(validate(&request(&s, "{}")).is_ok());
    for image in ["--privileged", "-v=/:/host", "a b", ""] {
        s.image = image.into();
        assert!(
            matches!(validate(&request(&s, "{}")), Err(RunError::Fatal(_))),
            "{image:?}"
        );
    }
    let s = spec(&["x"]);
    for id in ["../x", "a:b", "a/b", ""] {
        let mut r = request(&s, "{}");
        r.job_id = id;
        assert!(validate(&r).is_err(), "{id:?}");
    }
    // The process runner refuses too, before it starts anything.
    let mut bad = spec(&["true"]);
    bad.image = "--privileged".into();
    let e = ProcessRunner {
        requirements_dir: None,
    }
    .run(&request(&bad, "{}"), &AtomicBool::new(false))
    .unwrap_err();
    assert!(matches!(e, RunError::Fatal(_)));
}

#[test]
fn pinned_requirements_must_match_their_hash() {
    let dir = std::env::temp_dir().join(format!("falak-worker-req-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("scan.txt"), b"requests==2.32.0 --hash=sha256:aa\n").unwrap();
    let mut s = spec(&["x"]);
    // No pin: nothing to check.
    assert!(verify_requirements(Some(&dir), &s).unwrap().is_none());
    // Wrong hash, no directory: both refuse and neither retries.
    s.requirements_sha256 = Some("0".repeat(64));
    assert!(matches!(
        verify_requirements(Some(&dir), &s),
        Err(RunError::Fatal(_))
    ));
    assert!(matches!(
        verify_requirements(None, &s),
        Err(RunError::Fatal(_))
    ));
    // The right hash passes.
    use sha2::{Digest, Sha256};
    s.requirements_sha256 = Some(hex::encode(Sha256::digest(
        b"requests==2.32.0 --hash=sha256:aa\n",
    )));
    assert!(verify_requirements(Some(&dir), &s).unwrap().is_some());
}

#[test]
fn the_process_runner_passes_the_payload_and_returns_the_last_json_line() {
    let s = spec(&[
        "sh",
        "-c",
        "read p; echo log line; echo \"{\\\"echo\\\": $p}\"",
    ]);
    let out = ProcessRunner {
        requirements_dir: None,
    }
    .run(&request(&s, r#"{"a":1}"#), &AtomicBool::new(false))
    .unwrap();
    assert_eq!(out, Some(json!({"echo": {"a": 1}})));
}

#[test]
fn a_failing_job_is_reported_and_a_slow_one_is_killed() {
    let runner = ProcessRunner {
        requirements_dir: None,
    };
    let s = spec(&["sh", "-c", "echo oops >&2; exit 3"]);
    let e = runner
        .run(&request(&s, "{}"), &AtomicBool::new(false))
        .unwrap_err();
    assert!(
        matches!(&e, RunError::Failed(m) if m.contains("oops")),
        "{e:?}"
    );

    let mut slow = spec(&["sleep", "30"]);
    slow.timeout_seconds = 1;
    let started = std::time::Instant::now();
    let e = runner
        .run(&request(&slow, "{}"), &AtomicBool::new(false))
        .unwrap_err();
    assert!(matches!(&e, RunError::Failed(m) if m.contains("timed out")));
    assert!(started.elapsed().as_secs() < 10);
}

#[test]
fn cancelling_stops_the_job() {
    let s = spec(&["sleep", "30"]);
    let cancel = AtomicBool::new(false);
    let e = std::thread::scope(|sc| {
        let h = sc.spawn(|| {
            ProcessRunner {
                requirements_dir: None,
            }
            .run(&request(&s, "{}"), &cancel)
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        cancel.store(true, Ordering::SeqCst);
        h.join().unwrap()
    });
    assert!(matches!(e, Err(RunError::Cancelled)));
}
