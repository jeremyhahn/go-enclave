#!/usr/bin/env python3
"""runner-select-tests.py -- runs ci.yml's preflight step `Hosted or overflow
runner (ruling 1024)` (ci-template v1.48, Tenant Agent ruling 1024 item 1,
queue 250 (a)) against a fake Actions API and asserts the runs-on JSON it
outputs.

The code under test is read out of ci.yml, not copied: the `run: |` block of
the step named `Hosted or overflow runner (ruling 1024)`, found exactly once
or the test stops with FATAL (exit 9). It runs under `bash --noprofile
--norc -eo pipefail`, as the runner runs a step, with a fake `curl` first on
PATH that answers from canned replies; nothing reaches the network. The fake
also fails a case whose curl command line carries the token.

  A. The default: below HOSTED_JOBS_PER_REPO and no hosted job waiting gives
     "ubuntu-latest" for both classes; self-hosted jobs, completed jobs, a
     queued job of this run, and a queued job younger than the grace do not
     count.
  B. Overflow: HOSTED_JOBS_PER_REPO hosted jobs in progress, or a hosted job
     of another run queued for the grace or longer, gives the bigdisk and
     bigdisk-docker label lists, with a ::notice.
  C. No silent pick: a reply that is not 200, a reply with no total_count, a
     list short of its total that reaches no trigger (v1.50), or a threshold
     that is not a number gives the hosted default with a ::warning naming why.
     A short list is a lower bound: one that reaches a trigger overflows (B7).
  D. Off github.com: no call, the default output, the forge labels kept.
  E. ci-template v1.52 (Tenant Agent order): a pull request whose head
     repository is not this repository (a fork, or one since deleted) gets the
     hosted default with a ::notice and no call, even when the hosted pool is
     full; a same-repository pull request and a push still overflow, and off
     github.com a fork keeps the forge labels as before.

Run: python3 -I software/templates/github-actions/testdata/runner-select-tests.py
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
# The same file runs in the handbook (testdata/ beside the template) and in a
# carrier (testdata/ at the repository root), so the workflow is the
# template's, else the carrier's.
WORKFLOW = next((p for p in (HERE.parent / "ci.yml", HERE.parent / ".github" / "workflows" / "ci.yml") if p.exists()),
                HERE.parent / "ci.yml")
STEP = "      - name: Hosted or overflow runner (ruling 1024)\n"
TOKEN = "<fake-token-0123456789>"
FAILS = 0
HOSTED = '"ubuntu-latest"'
OVER = '["self-hosted","linux","x64","bigdisk"]'
OVER_D = '["self-hosted","linux","x64","bigdisk-docker"]'


def fatal(msg):
    print(f"FATAL: {msg}")
    sys.exit(9)


def script():
    text = WORKFLOW.read_text()
    if text.count(STEP) != 1:
        fatal("the step `Hosted or overflow runner (ruling 1024)` is not in ci.yml exactly once")
    rest = text.split(STEP, 1)[1].split("\n")
    out, inside = [], False
    for line in rest:
        if not inside:
            if line == "        run: |":
                inside = True
            elif line.startswith("      - "):
                break
            continue
        if line.strip() and not line.startswith(" " * 10):
            break
        out.append(line[10:])
    if not out:
        fatal("the step's run block is not found")
    return "\n".join(out) + "\n"


SCRIPT = script()

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if any(os.environ["FAKE_TOKEN"] in a for a in args):
    print("token on the curl command line", file=sys.stderr)
    sys.exit(97)
out = args[args.index("-o") + 1]
url = args[-1]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(url + "\n")
for key, code, body in json.load(open(os.environ["FAKE_RESP"])):
    if key in url:
        with open(out, "w") as f:
            f.write(body)
        sys.stdout.write(str(code))
        sys.exit(0)
with open(out, "w") as f:
    f.write('{"message":"Not Found"}')
sys.stdout.write("404")
'''


def iso(age):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))


def jobj(run, status, labels, age=5):
    return {"run_id": run, "status": status, "labels": labels, "created_at": iso(age), "started_at": iso(age)}


def runs(*ids, total=None):
    return json.dumps({"total_count": len(ids) if total is None else total, "workflow_runs": [{"id": i} for i in ids]})


def jobs(*js, total=None):
    return json.dumps({"total_count": len(js) if total is None else total, "jobs": list(js)})


def run(resp, server="https://github.com", limit="12", grace="60", event="push", head=""):
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "bin").mkdir()
        curl = d / "bin" / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(0o755)
        (d / "resp.json").write_text(json.dumps(resp))
        (d / "out").write_text("")
        (d / "log").write_text("")
        (d / "tmp").mkdir()
        (d / "step.sh").write_text(SCRIPT)
        env = {
            "PATH": f"{d / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "FAKE_RESP": str(d / "resp.json"), "FAKE_LOG": str(d / "log"), "FAKE_TOKEN": TOKEN,
            "GITHUB_OUTPUT": str(d / "out"), "RUNNER_TEMP": str(d / "tmp"),
            "SERVER": server, "API": "https://api.github.com/repos/o/r/actions", "RUN_ID": "100",
            "JOB_TOKEN": TOKEN, "LIMIT": limit, "GRACE": grace,
            "EVENT": event, "HEAD_REPO": head, "REPO": "o/r",
        }
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(d / "step.sh")],
                           env=env, capture_output=True, text=True, timeout=60)
        outs = dict(l.split("=", 1) for l in (d / "out").read_text().splitlines() if "=" in l)
        return p.returncode, p.stdout + p.stderr, outs, (d / "log").read_text().splitlines()


def case(label, resp, runner, docker, want=(), not_want=(), calls=None, **kw):
    global FAILS
    rc, out, outs, log = run(resp, **kw)
    ok = (rc == 0 and outs.get("runner") == runner and outs.get("runner_docker") == docker
          and all(w in out for w in want) and not any(w in out for w in not_want)
          and (calls is None or len(log) == calls) and TOKEN not in out)
    print(f"{'PASS' if ok else 'FAIL'}: {label}")
    if not ok:
        FAILS += 1
        print(f"  exit {rc}; outputs {outs}; wanted runner={runner} runner_docker={docker}; calls {len(log)}")
        print("  " + out.replace("\n", "\n  "))


U = ["ubuntu-latest"]
SH = ["self-hosted", "linux", "x64", "bigdisk-docker"]


def api(queued, in_progress, per_run):
    r = [["runs?status=queued", 200, queued], ["runs?status=in_progress", 200, in_progress]]
    return r + [[f"runs/{i}/jobs", 200, body] for i, body in per_run.items()]


# A. the default
case("A1 nothing in flight but this run: hosted",
     api(runs(), runs(100), {100: jobs(jobj(100, "in_progress", U))}), HOSTED, HOSTED,
     ["1 hosted job(s) in progress"], ["::warning::", "::notice::"])
case("A2 eleven hosted jobs in progress: hosted",
     api(runs(), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)),
                                  101: jobs(*[jobj(101, "in_progress", ["ubuntu-24.04"]) for _ in range(10)])}),
     HOSTED, HOSTED, ["11 hosted job(s) in progress"])
case("A3 self-hosted and completed jobs do not count",
     api(runs(), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)),
                                  101: jobs(*[jobj(101, "in_progress", SH) for _ in range(20)],
                                            *[jobj(101, "completed", U) for _ in range(20)],
                                            jobj(101, "in_progress", ["self-hosted", "ubuntu-latest"]))}),
     HOSTED, HOSTED, ["1 hosted job(s) in progress"])
case("A4 a queued job of this run does not count",
     api(runs(), runs(100), {100: jobs(jobj(100, "in_progress", U), jobj(100, "queued", U, age=600))}),
     HOSTED, HOSTED, ["0 hosted job(s) of other runs queued"])
case("A5 a queued hosted job younger than the grace does not count",
     api(runs(102), runs(100), {100: jobs(jobj(100, "in_progress", U)), 102: jobs(jobj(102, "queued", U, age=5))}),
     HOSTED, HOSTED, ["0 hosted job(s) of other runs queued"])
case("A6 a self-hosted job queued long does not count",
     api(runs(102), runs(100), {100: jobs(jobj(100, "in_progress", U)), 102: jobs(jobj(102, "queued", SH, age=900))}),
     HOSTED, HOSTED)

# B. overflow
case("B1 twelve hosted jobs in progress: overflow",
     api(runs(), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)),
                                  101: jobs(*[jobj(101, "in_progress", U) for _ in range(11)])}),
     OVER, OVER_D, ["::notice::", "12 hosted jobs in progress", "HOSTED_JOBS_PER_REPO=12"])
case("B2 a hosted job of another run queued past the grace: overflow",
     api(runs(102), runs(100), {100: jobs(jobj(100, "in_progress", U)), 102: jobs(jobj(102, "queued", U, age=120))}),
     OVER, OVER_D, ["::notice::", "the hosted pool is full"])
case("B3 a queued job inside an in-progress run counts",
     api(runs(), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)),
                                  101: jobs(jobj(101, "in_progress", U), jobj(101, "queued", U, age=300))}),
     OVER, OVER_D, ["the hosted pool is full"])
case("B4 the threshold is HOSTED_JOBS_PER_REPO",
     api(runs(), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)), 101: jobs(jobj(101, "in_progress", U))}),
     OVER, OVER_D, ["HOSTED_JOBS_PER_REPO=2"], limit="2")
case("B5 a run listed as queued and as in progress is counted once",
     api(runs(101), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)),
                                     101: jobs(*[jobj(101, "in_progress", U) for _ in range(6)])}),
     HOSTED, HOSTED, ["7 hosted job(s) in progress"])
case("B6 a second page is read",
     [["runs?status=queued", 200, runs()],
      ["runs?status=in_progress&per_page=100&page=1", 200, runs(100, total=2)],
      ["runs?status=in_progress&per_page=100&page=2", 200, runs(101, total=2)],
      ["runs/100/jobs", 200, jobs(jobj(100, "in_progress", U))],
      ["runs/101/jobs", 200, jobs(*[jobj(101, "in_progress", U) for _ in range(11)])]],
     OVER, OVER_D, ["12 hosted jobs in progress"])
case("B7 a queued list short of its total still overflows on what it read (v1.50)",
     [["runs?status=queued&per_page=100&page=1", 200, runs(102, total=3)],
      ["runs?status=queued&per_page=100&page=2", 200, runs(total=3)],
      ["runs?status=in_progress", 200, runs(100)],
      ["runs/100/jobs", 200, jobs(jobj(100, "in_progress", U))],
      ["runs/102/jobs", 200, jobs(jobj(102, "queued", U, age=600))]],
     OVER, OVER_D, ["::notice::", "the hosted pool is full", "a lower bound", "1 of 3 entries"], ["::warning::"])

# C. no silent pick
case("C1 a 403 on the run list: hosted, with a warning naming why",
     [["runs?status=queued", 403, '{"message":"Resource not accessible by integration"}']],
     HOSTED, HOSTED, ["::warning::runner selection: the Actions API gave no complete run list", "403", "ubuntu-latest"])
case("C2 a 500 on a job list: hosted, with a warning",
     api(runs(), runs(100), {}) + [["runs/100/jobs", 500, "{}"]],
     HOSTED, HOSTED, ["::warning::", "no complete job list", "500"])
case("C3 a 200 with no total_count: hosted, with a warning",
     [["runs?status=queued", 200, '{"workflow_runs":[]}']],
     HOSTED, HOSTED, ["::warning::", "no total_count"])
case("C4 a list short of its total that reaches no trigger: hosted, with a warning",
     [["runs?status=queued", 200, runs()],
      ["runs?status=in_progress&per_page=100&page=1", 200, runs(100, total=5)],
      ["runs?status=in_progress&per_page=100&page=2", 200, runs(total=5)],
      ["runs/100/jobs", 200, jobs(jobj(100, "in_progress", U))]],
     HOSTED, HOSTED, ["::warning::", "1 of 5 entries"])
case("C5 a threshold that is not a number: hosted, with a warning, no call",
     [], HOSTED, HOSTED, ["::warning::", "not a whole number"], calls=0, limit="twelve")
case("C6 an empty threshold: hosted, with a warning",
     [], HOSTED, HOSTED, ["::warning::", "not a whole number"], calls=0, limit="")
case("C7 a job with no created_at: hosted, with a warning",
     api(runs(102), runs(100), {100: jobs(jobj(100, "in_progress", U)),
                                102: jobs({"run_id": 102, "status": "queued", "labels": U})}),
     HOSTED, HOSTED, ["::warning::", "could not be counted"])
case("C8 a route the API does not answer (404): hosted, with a warning",
     [], HOSTED, HOSTED, ["::warning::", "404"])

# D. off github.com
case("D1 Gitea: no call, the default output",
     [], HOSTED, HOSTED, ["not github.com"], ["::warning::"], calls=0, server="https://forge.example")

# E. a fork's pull request (v1.52)
FULL = api(runs(), runs(100, 101), {100: jobs(jobj(100, "in_progress", U)),
                                    101: jobs(*[jobj(101, "in_progress", U) for _ in range(11)])})
case("E1 a fork's pull request with the hosted pool full: hosted, no call",
     FULL, HOSTED, HOSTED, ["::notice::", "a fork", "ci-template v1.52"], ["::warning::"], calls=0,
     event="pull_request", head="fork/r")
case("E2 a pull request whose head repository is gone: hosted, no call",
     FULL, HOSTED, HOSTED, ["a fork"], calls=0, event="pull_request", head="")
case("E3 a fork under pull_request_target: hosted, no call",
     FULL, HOSTED, HOSTED, ["a fork"], calls=0, event="pull_request_target", head="fork/r")
case("E4 a same-repository pull request with the hosted pool full still overflows",
     FULL, OVER, OVER_D, ["::notice::", "12 hosted jobs in progress"], ["a fork"], event="pull_request", head="o/r")
case("E5 a push with the hosted pool full still overflows",
     FULL, OVER, OVER_D, ["12 hosted jobs in progress"], ["a fork"])
case("E6 off github.com a fork keeps the forge labels: no call, no fork notice",
     [], HOSTED, HOSTED, ["not github.com"], ["a fork"], calls=0, server="gitea", event="pull_request", head="fork/r")

print(f"{'ALL PASS' if not FAILS else f'{FAILS} FAILED'}")
sys.exit(1 if FAILS else 0)
