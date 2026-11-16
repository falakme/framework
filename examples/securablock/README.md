# SecuraBlock

Scan code and artifact bundles for leaked secrets. A person asks for a scan; the scan is a
**compute job** (`jobs/scan_artifact.yaml`) that a worker you run picks up. The worker only
calls out to Office; nothing connects in.

* `worker/scan.py` is the job. `worker/Dockerfile` builds its image; the worker runs it as
  an unprivileged user, read-only, with no network.
* `scripts/smoke/compute.sh` queues a long scan, kills the worker part-way, and checks the
  job still finishes exactly once.
