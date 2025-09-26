# SRETools

Awesome brief. Here’s a compact, glue-code toolkit you can drop on any Linux box to (roughly) emulate the “8 Essential Monitoring Tools”—using only shell + Python. You’ll get collectors, background jobs (cron/systemd), local storage, simple alerting, and optional Prometheus-compatible endpoints so you can later plug in real backends if you want.

---

# 0) Layout

```text
baremon/
├─ collectors/
│  ├─ sysprobe.sh                # CPU/mem/disk/net snapshots → TSV
│  ├─ http_probe.sh              # SiteScope-style HTTP checks → JSONL
│  ├─ port_probe.sh              # TCP port checks → JSONL
│  ├─ proc_stats.py              # psutil system metrics → JSONL (+/metrics)
│  ├─ apm_mw.py                  # Tiny WSGI/ASGI timing middleware (APM-lite)
│  └─ log_watcher.py             # Error tracking by tailing logs (Sentry-lite)
├─ storage/
│  ├─ metrics/                   # Rolling TSV/JSONL files
│  └─ logs/
├─ alerting/
│  ├─ thresholds.yml             # Human-readable alert thresholds
│  ├─ evaluate.py                # Reads metrics + thresholds → alerts
│  └─ notify.sh                  # Email/Slack/MS Teams webhook notifier
├─ viz/
│  └─ render_daily.py            # Quick matplotlib PNG charts (Grafana-lite)
├─ ops/
│  ├─ systemd/
│  │  ├─ baremon-collect.service
│  │  ├─ baremon-collect.timer
│  │  ├─ baremon-alerts.service
│  │  └─ baremon-alerts.timer
│  └─ crontab.example
└─ README.md
```

> All scripts write plain TSV/JSONL so you can `cat`, `jq`, `awk`, or throw them into SQLite/Parquet later.

---

# 1) Collectors (metrics, uptime, checks)

## 1.1 System snapshot (shell)

```bash
#!/usr/bin/env bash
# collectors/sysprobe.sh
set -euo pipefail
OUT_DIR="${1:-$(dirname "$0")/../storage/metrics}"
mkdir -p "$OUT_DIR"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HOST=$(hostname)

CPU_LOAD=$(awk '{print $1","$2","$3}' /proc/loadavg)
MEM=$(free -m | awk '/Mem:/ {print $2","$3","$7}')          # total,used,free(MiB)
DISK=$(df -P -k / | awk 'NR==2 {print $2","$3","$4}')       # 1K-blocks: total,used,avail
NET_RX=$(cat /sys/class/net/*/statistics/rx_bytes 2>/dev/null | paste -sd+ - | bc)
NET_TX=$(cat /sys/class/net/*/statistics/tx_bytes 2>/dev/null | paste -sd+ - | bc)

echo -e "ts\thost\tload1,5,15\tmemMB(t,u,f)\tdiskKB(t,u,a)\tnet(rx,tx)"
echo -e "${TS}\t${HOST}\t${CPU_LOAD}\t${MEM}\t${DISK}\t${NET_RX},${NET_TX}" \
  | tee -a "${OUT_DIR}/sysprobe.tsv" > /dev/null
```

## 1.2 psutil agent (Python) with optional Prometheus `/metrics`

```python
# collectors/proc_stats.py
import time, json, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import psutil

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "metrics")
os.makedirs(OUT_DIR, exist_ok=True)

def collect_once():
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    d = {
        "ts": ts,
        "host": os.uname().nodename,
        "cpu_pct": psutil.cpu_percent(interval=0.2),
        "mem": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "net": psutil.net_io_counters()._asdict(),
        "procs": len(psutil.pids()),
        "uptime_s": int(time.time() - psutil.boot_time()),
    }
    with open(os.path.join(OUT_DIR, "proc_stats.jsonl"), "a") as f:
        f.write(json.dumps(d) + "\n")
    return d

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":  # Prometheus text exposition
            d = collect_once()
            txt = []
            txt.append(f'cpu_percent {d["cpu_pct"]}')
            txt.append(f'memory_used_bytes {d["mem"]["used"]}')
            txt.append(f'memory_total_bytes {d["mem"]["total"]}')
            txt.append(f'disk_used_bytes {d["disk"]["used"]}')
            txt.append(f'disk_total_bytes {d["disk"]["total"]}')
            txt.append(f'net_bytes_sent {d["net"]["bytes_sent"]}')
            txt.append(f'net_bytes_recv {d["net"]["bytes_recv"]}')
            txt.append(f'process_count {d["procs"]}')
            txt.append(f'uptime_seconds {d["uptime_s"]}')
            out = "\n".join(txt) + "\n"
            self.send_response(200); self.send_header("Content-Type","text/plain"); self.end_headers()
            self.wfile.write(out.encode())
        else:
            self.send_response(404); self.end_headers()

def run_http():
    port = int(os.environ.get("BAREMON_METRICS_PORT", "9100"))
    HTTPServer(("0.0.0.0", port), H).serve_forever()

if __name__ == "__main__":
    # background HTTP exporter
    t = threading.Thread(target=run_http, daemon=True); t.start()
    # foreground periodic collector
    interval = int(os.environ.get("BAREMON_INTERVAL_S", "60"))
    while True:
        collect_once()
        time.sleep(interval)
```

## 1.3 HTTP uptime & latency (SiteScope-style)

```bash
#!/usr/bin/env bash
# collectors/http_probe.sh  <url> [timeout_s]
set -euo pipefail
URL="${1:?url required}"; TO="${2:-10}"
OUT_DIR="$(dirname "$0")/../storage/metrics"; mkdir -p "$OUT_DIR"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUS_TIME=$(curl -sS -o /dev/null -w '%{http_code} %{time_total}' --max-time "$TO" "$URL" || echo "000 $TO")
CODE=$(echo "$STATUS_TIME" | awk '{print $1}'); T=$(echo "$STATUS_TIME" | awk '{print $2}')
jq -n --arg ts "$TS" --arg url "$URL" --arg code "$CODE" --arg t "$T" \
  '{ts:$ts,url:$url,status:($code|tonumber),seconds:($t|tonumber)}' \
  >> "$OUT_DIR/http_probe.jsonl"
```

## 1.4 Port check

```bash
#!/usr/bin/env bash
# collectors/port_probe.sh  <host> <port>
set -euo pipefail
H="${1:?host}"; P="${2:?port}"
OUT_DIR="$(dirname "$0")/../storage/metrics"; mkdir -p "$OUT_DIR"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if timeout 3 bash -c "</dev/tcp/$H/$P" 2>/dev/null; then UP=true; else UP=false; fi
jq -n --arg ts "$TS" --arg h "$H" --argjson p "$P" --argjson up "$UP" \
  '{ts:$ts,host:$h,port:$p,up:$up}' >> "$OUT_DIR/port_probe.jsonl"
```

---

# 2) Error Tracking (Sentry-lite)

Watches files/journald for `ERROR|Exception|Traceback|CRITICAL` and emits JSON events + optional Slack ping.

```python
# collectors/log_watcher.py
import os, re, json, time, subprocess, sys
OUT = os.path.join(os.path.dirname(__file__), "..", "storage", "logs")
os.makedirs(OUT, exist_ok=True)
PAT = re.compile(r"(ERROR|Exception|Traceback|CRITICAL)", re.I)

def stream_journal():
    p = subprocess.Popen(["journalctl","-f","-o","short"], stdout=subprocess.PIPE, text=True)
    for line in iter(p.stdout.readline, ""):
        yield {"source":"journald", "line":line.rstrip()}

def stream_file(path):
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2); continue
            yield {"source":path, "line":line.rstrip()}

def main(paths):
    streams = [stream_journal()] if not paths else [stream_file(p) for p in paths]
    while True:
        for s in streams:
            try:
                ev = next(s)
                if PAT.search(ev["line"]):
                    ev["ts"]=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    with open(os.path.join(OUT,"errors.jsonl"),"a") as f:
                        f.write(json.dumps(ev)+"\n")
            except StopIteration:
                pass

if __name__=="__main__":
    main(sys.argv[1:])
```

---

# 3) Alerting (PagerDuty-lite)

## 3.1 Thresholds

```yaml
# alerting/thresholds.yml
cpu_percent: {gt: 90, for_seconds: 300}
memory_used_ratio: {gt: 0.9, for_seconds: 300}
disk_used_ratio: {gt: 0.9, path: "/"}
http_latency_seconds: {gt: 1.5, url: "https://example.com"}
http_status_not: {neq: 200, url: "https://example.com"}
```

## 3.2 Evaluator

```python
# alerting/evaluate.py
import os, json, time, yaml, statistics, requests

BASE = os.path.join(os.path.dirname(__file__), "..", "storage", "metrics")

def tail_jsonl(path, seconds=300):
    cutoff = time.time() - seconds
    out=[]
    try:
        with open(path) as f:
            for line in f:
                d=json.loads(line)
                # naive timestamp parse
                t=time.mktime(time.strptime(d["ts"], "%Y-%m-%dT%H:%M:%SZ"))
                if t>=cutoff: out.append(d)
    except FileNotFoundError:
        pass
    return out

def notify(msg):
    os.system(f'./alerting/notify.sh "{msg}"')

def main():
    cfg = yaml.safe_load(open(os.path.join(os.path.dirname(__file__),"thresholds.yml")))
    # CPU
    if "cpu_percent" in cfg:
        rows = tail_jsonl(os.path.join(BASE,"proc_stats.jsonl"), cfg["cpu_percent"]["for_seconds"])
        vals=[r.get("cpu_pct",0) for r in rows]
        if vals and statistics.mean(vals) > cfg["cpu_percent"]["gt"]:
            notify(f"ALERT cpu > {cfg['cpu_percent']['gt']} avg={statistics.mean(vals):.1f}%")

    # Memory
    if "memory_used_ratio" in cfg:
        rows = tail_jsonl(os.path.join(BASE,"proc_stats.jsonl"), cfg["memory_used_ratio"]["for_seconds"])
        vals=[r["mem"]["percent"]/100.0 for r in rows if "mem" in r]
        if vals and statistics.mean(vals) > cfg["memory_used_ratio"]["gt"]:
            notify(f"ALERT memory ratio > {cfg['memory_used_ratio']['gt']} avg={statistics.mean(vals):.2f}")

    # Disk
    if "disk_used_ratio" in cfg:
        rows = tail_jsonl(os.path.join(BASE,"proc_stats.jsonl"), 600)
        vals=[r["disk"]["percent"]/100.0 for r in rows if "disk" in r]
        if vals and statistics.mean(vals) > cfg["disk_used_ratio"]["gt"]:
            notify(f"ALERT disk ratio > {cfg['disk_used_ratio']['gt']} avg={statistics.mean(vals):.2f}")

    # HTTP latency/status
    if "http_latency_seconds" in cfg:
        rows = tail_jsonl(os.path.join(BASE,"http_probe.jsonl"), 600)
        rows = [r for r in rows if r["url"]==cfg["http_latency_seconds"]["url"]]
        vals=[r["seconds"] for r in rows]
        if vals and statistics.mean(vals) > cfg["http_latency_seconds"]["gt"]:
            notify(f"ALERT http latency {cfg['http_latency_seconds']['url']} avg={statistics.mean(vals):.2f}s")

    if "http_status_not" in cfg:
        rows = tail_jsonl(os.path.join(BASE,"http_probe.jsonl"), 600)
        rows = [r for r in rows if r["url"]==cfg["http_status_not"]["url"]]
        bad=[r for r in rows if r["status"]!=cfg["http_status_not"]["neq"]]
        if bad:
            notify(f"ALERT http status {cfg['http_status_not']['url']} saw {bad[-1]['status']}")

if __name__=="__main__":
    main()
```

## 3.3 Notifier (email/Slack)

```bash
#!/usr/bin/env bash
# alerting/notify.sh  "message"
set -euo pipefail
MSG="${1:?message}"
echo "[BareMon] $MSG"

# Email (requires local MTA or ssmtp)
if command -v mail >/dev/null 2>&1; then
  echo "$MSG" | mail -s "[BareMon]" ops@example.com || true
fi

# Slack webhook (set SLACK_WEBHOOK_URL env)
if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  curl -s -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"$MSG\"}" "$SLACK_WEBHOOK_URL" >/dev/null || true
fi
```

---

# 4) Visualization (Grafana-lite)

Daily PNGs; drop them in `/var/www/html/metrics/` if you want.

```python
# viz/render_daily.py
import json, os, time, matplotlib.pyplot as plt
from datetime import datetime, timedelta

BASE = os.path.join(os.path.dirname(__file__), "..", "storage", "metrics")
OUT = os.path.join(os.path.dirname(__file__), "..", "storage")

def load_series(path, key):
    xs, ys = [], []
    with open(path) as f:
        for line in f:
            d=json.loads(line)
            xs.append(datetime.strptime(d["ts"], "%Y-%m-%dT%H:%M:%SZ"))
            ys.append(eval(key, {}, {"d":d}))  # e.g., "d['cpu_pct']"
    return xs, ys

def plot(xs, ys, title, fname):
    plt.figure()
    plt.plot(xs, ys)
    plt.title(title); plt.xlabel("time"); plt.ylabel(title)
    plt.tight_layout(); plt.savefig(os.path.join(OUT, fname)); plt.close()

if __name__=="__main__":
    p = os.path.join(BASE,"proc_stats.jsonl")
    if os.path.exists(p):
        xs, ys = load_series(p, "d['cpu_pct']")
        plot(xs, ys, "CPU %", "cpu_today.png")
        xs, ys = load_series(p, "d['mem']['percent']")
        plot(xs, ys, "Mem %", "mem_today.png")
```

---

# 5) Background Jobs

## Option A: systemd timers (recommended)

```ini
# ops/systemd/baremon-collect.service
[Unit] Description=BareMon Collectors
[Service]
Type=oneshot
WorkingDirectory=/opt/baremon
ExecStart=/bin/bash -lc './collectors/sysprobe.sh && \
                         python3 collectors/proc_stats.py & sleep 1 && \
                         ./collectors/http_probe.sh https://example.com 5 && \
                         ./collectors/port_probe.sh localhost 22'

# ops/systemd/baremon-collect.timer
[Unit] Description=Run BareMon collectors every minute
[Timer] OnCalendar=*-*-* *:*:00
[Install] WantedBy=timers.target

# ops/systemd/baremon-alerts.service
[Unit] Description=BareMon Evaluate Alerts
[Service] Type=oneshot
WorkingDirectory=/opt/baremon
ExecStart=/usr/bin/python3 alerting/evaluate.py

# ops/systemd/baremon-alerts.timer
[Unit] Description=Run BareMon alerts every 2 minutes
[Timer] OnUnitActiveSec=2min
[Install] WantedBy=timers.target
```

Enable:

```bash
sudo cp -r baremon /opt/baremon
cd /opt/baremon
sudo cp ops/systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now baremon-collect.timer baremon-alerts.timer
```

## Option B: cron (simple)

```cron
# ops/crontab.example
* * * * *  /opt/baremon/collectors/sysprobe.sh
* * * * *  /usr/bin/python3 /opt/baremon/collectors/proc_stats.py
*/2 * * * * /usr/bin/python3 /opt/baremon/alerting/evaluate.py
0 * * * *   /usr/bin/python3 /opt/baremon/viz/render_daily.py
```

---

# 6) APM-lite (New Relic replacement flavor)

Drop this middleware into Python apps to time requests and log them into JSONL.

```python
# collectors/apm_mw.py
import time, json, os
OUT = os.path.join(os.path.dirname(__file__), "..", "storage", "metrics")
os.makedirs(OUT, exist_ok=True)

class WsgiAPM:
    def __init__(self, app): self.app = app
    def __call__(self, environ, start_response):
        t0 = time.time()
        status_code = [200]
        def _sr(status, headers, exc_info=None):
            status_code[0] = int(status.split()[0]); return start_response(status, headers, exc_info)
        res = self.app(environ, _sr)
        dur = time.time()-t0
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "path": environ.get("PATH_INFO","/"),
               "method": environ.get("REQUEST_METHOD","GET"),
               "status": status_code[0], "seconds": dur}
        with open(os.path.join(OUT,"apm.jsonl"),"a") as f: f.write(json.dumps(rec)+"\n")
        return res
```

(ASGI version is similar—wrap `__call__` with `async` and measure before/after `await app(scope, receive, send)`.)

---

# 7) How these DIY pieces map to the “8 Essentials”

| Category / Tool                     | What the commercial tool gives you                  | DIY replacement here                                                                                                  | Where this works                         | Where it falls short                                                         |
| ----------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------- |
| **Prometheus (Metrics Monitoring)** | Pull-based scraping, TSDB, flexible queries, alerts | `proc_stats.py` exposes **/metrics** (Prometheus text). Use it *alone* to view metrics, or add real Prometheus later. | Lightweight node metrics on any box      | No TSDB, no PromQL until you add Prometheus/VM-Agent/etc.                    |
| **Sentry (Error Tracking)**         | Exception grouping, releases, PII scrubbing         | `log_watcher.py` to tail logs/journald + regex → `errors.jsonl`; alert via `notify.sh`.                               | Quick error feeds without agents         | No grouping/de-dup, no UI, manual scrubbing.                                 |
| **Grafana (Visualization)**         | Dashboards, alerts, plugins                         | `viz/render_daily.py` makes PNG charts; or just point Grafana at `proc_stats.py` exporter if later added.             | Daily graphs for ops reports, zero infra | Not interactive; limited panels; no templating.                              |
| **Datadog (Full-stack)**            | Infra + APM + logs + synthetics + security          | Combine: `sysprobe.sh` + `proc_stats.py` + `http_probe.sh` + `apm_mw.py` + `log_watcher.py` + `evaluate.py`.          | Cost-free starter pack                   | Missing rich UI, advanced correlations, cloud autodiscovery.                 |
| **SiteScope (Infra Monitoring)**    | Agentless checks: HTTP/Port/CPU/etc                 | `http_probe.sh` and `port_probe.sh` cron/systemd timers                                                               | Simple uptime/latency checks             | No device inventory, limited protocols, no SNMP UI.                          |
| **ELK Stack (Logging)**             | Centralized ingest, search, dashboards              | Keep JSONL under `storage/`. If you need search: `ripgrep`/`jq`, or ingest later to SQLite/Logstash/Vector.           | Tiny footprint, text-first ops           | No distributed search; recommend adding Vector→OpenSearch later.             |
| **New Relic (APM)**                 | Tracing, RUM, service maps                          | `apm_mw.py` (Python) + JSONL timings; add OpenTelemetry SDKs later for real tracing.                                  | Per-endpoint latency/error rate          | No spans/service map; language-specific work needed.                         |
| **PagerDuty (Alerting)**            | Rotations, escalations, on-call app                 | `thresholds.yml` + `evaluate.py` + `notify.sh` (email/Slack/MS Teams)                                                 | Basic threshold alerts to a channel      | No schedules/escalations; integrate with OpsGenie/PagerDuty later if needed. |

---

# 8) Quickstart (5 minutes)

```bash
sudo apt-get update && sudo apt-get install -y jq python3-pip mailutils
pip3 install psutil pyyaml matplotlib

git clone https://example.com/your/baremon.git   # or copy files
sudo cp -r baremon /opt/baremon
cd /opt/baremon

# one-shot run
./collectors/sysprobe.sh
python3 collectors/proc_stats.py &   # keeps an HTTP /metrics on :9100
./collectors/http_probe.sh https://example.com 5

# enable background jobs (systemd)
sudo cp ops/systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now baremon-collect.timer baremon-alerts.timer
```

Visit: `http://<host>:9100/metrics` for Prometheus-format metrics.

---

# 9) Hardening & Ops Tips

* **logrotate**: rotate `storage/*/*.jsonl`/TSV daily with gzip.
* **namespacing**: prefix host or role in filenames if shipping to NFS.
* **security**: bind `/metrics` to `127.0.0.1` behind NGINX if public box.
* **shipping later**: add Vector/Fluent Bit to forward JSONL to OpenSearch/Loki.
* **containerize**: wrap collectors in a tiny Docker image and run via Compose/Swarm/K8s DaemonSet.
* **OTel on-ramp**: you can swap `apm_mw.py` for OpenTelemetry SDK to gain traces while keeping the rest.

---

If you want, I can package this as a ready-to-run Git repo (or a tar.gz) with a Makefile and a Dockerfile so you can drop it on your fleet.
