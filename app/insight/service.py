"""
The seven server tools, for one SSH pane at a time.

Each pane connected with `ssh` gets an Insight: who the server is (asked once),
a health monitor that keeps its history between readings, at most one
performance check running, and the last log and package reports, so the AI
analysis and the vulnerability scan build on what was already read instead of
reading it again.

Everything learned is filed against the server's own identity in the history
(``servers.json`` in the data folder), so a server reached at a new address,
or through a jump host, keeps one history.

The AI analyses never send anything without the person seeing it first: a
``preview`` returns exactly the text that would be sent, and only a request
that carries that same text back sends it.
"""

import dataclasses
import json
import os
import threading
import time

from app import agent, remote
from app.insight import health, inventory, perfcheck, serverinsight as insight, vulnscan

# The AI prompts and limits are ARES Ultimate Console's (ares/assistant.py),
# kept word for word so the two products diagnose a server the same way.
MAX_LOG_EXCERPT = 24 * 1024
MAX_PERF_PACK = 96 * 1024

LOG_PROMPT = """You analyse error logs from a server for the system \
administrator responsible for it.

You are given recurring error patterns with their counts, then the newest raw \
error lines. Secrets have been replaced with *** or <token> before you saw them.

Answer in this shape, in plain text with short markdown lists:

1. Verdict - one sentence: is this server in trouble, degraded, or just noisy?
2. Problems, worst first - for each: what is failing, the evidence (quote the \
pattern and its count), the likely cause, and the first command to run to \
confirm it.
3. Noise - patterns that look alarming but are usually harmless, so they can be \
ignored or silenced.

Be concrete and brief. Never invent a log line, a count, a unit name or a path \
that is not in what you were given - say what you would check instead. A wrong \
diagnosis acted on in production is worse than "not enough evidence"."""

PERF_PROMPT = """You investigate performance problems on a Linux server for \
the system administrator responsible for it.

You are given a performance analysis pack: what was sampled and how, a \
summary, the rule-based findings, tables of processes, memory, network and \
connections, and a time series. Anything that looked like a credential in a \
command line has been replaced with *** before you saw it.

Answer in markdown with exactly these sections:

## Diagnosis
One or two sentences: what best explains the CPU, the load and the memory, \
and whether it is a problem.

## Evidence
The numbers from the pack that support the diagnosis - quote them.

## Recommended actions
In order, each with the command to run or the setting to change.

## If that does not fix it
What to check next, and what evidence would confirm it.

Never invent a process, a number or a path that is not in the pack - say what \
you would measure instead. A wrong diagnosis acted on in production is worse \
than "not enough evidence"."""


class InsightError(Exception):
    """Something to show the person, in words."""


def plain(obj):
    """A report as JSON-able data: dataclasses, properties that matter, sets."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out = {f.name: plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
        for extra in ("severity", "short", "total", "exposed", "local_only", "label",
                      "guessed", "managers", "url"):
            if hasattr(type(obj), extra) and isinstance(getattr(type(obj), extra), property):
                try:
                    out[extra] = plain(getattr(obj, extra))
                except Exception:
                    pass
        return out
    if isinstance(obj, dict):
        return {str(k): plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [plain(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def verdict_line(answer: str) -> str:
    """The first real sentence of an AI answer, for the history's title."""
    for line in (answer or "").splitlines():
        line = line.strip().lstrip("#").strip()
        line = line.split("Verdict", 1)[-1].lstrip(" -:*.1") if "Verdict" in line else line
        if len(line) > 12 and not line.lower().startswith(("diagnosis", "## ")):
            return line.strip("* ")
    return ""


# ------------------------------------------------------------------ history

class ServerHistory:
    """What has been seen and studied on each server, keyed by its identity.

    One JSON file, written whole under a lock -- the same bargain as the
    connection history. Bodies are the reports' plain text, capped, so a
    year of checks on fifty servers stays a few megabytes.
    """

    MAX_EVENTS = 200
    MAX_BODY = 60_000

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"servers": {}}
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded.get("servers"), dict):
                self.data = loaded
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh)
        os.replace(tmp, self.path)

    def note_server(self, ident, connection: str) -> None:
        now = time.time()
        with self.lock:
            s = self.data["servers"].setdefault(ident.uid, {
                "uid": ident.uid, "first_seen": now, "connections": [], "events": []})
            s.update(last_seen=now, source=ident.source, hostname=ident.hostname,
                     os_name=ident.os_name, kernel=ident.kernel, platform=ident.platform,
                     addresses=list(ident.addresses or [])[:12], container=ident.container)
            if connection and connection not in s["connections"]:
                s["connections"] = ([connection] + s["connections"])[:20]
            self._save()

    def add(self, uid: str, kind: str, title: str, severity: str, body: str,
            connection: str) -> None:
        with self.lock:
            s = self.data["servers"].get(uid)
            if s is None:
                return
            s["events"].insert(0, {"t": time.time(), "kind": kind, "title": title[:300],
                                   "severity": severity, "connection": connection,
                                   "body": (body or "")[:self.MAX_BODY]})
            del s["events"][self.MAX_EVENTS:]
            self._save()

    def get(self, uid: str):
        with self.lock:
            s = self.data["servers"].get(uid)
            return json.loads(json.dumps(s)) if s else None

    def servers(self) -> list:
        with self.lock:
            return sorted(({k: v for k, v in s.items() if k != "events"}
                           | {"events": len(s["events"])}
                           for s in self.data["servers"].values()),
                          key=lambda s: -s.get("last_seen", 0))

    def forget(self, uid: str) -> bool:
        with self.lock:
            gone = self.data["servers"].pop(uid, None) is not None
            if gone:
                self._save()
            return gone


# ------------------------------------------------------------------ one pane

class Insight:
    def __init__(self, sid: str, command: str, history: ServerHistory):
        self.sid = sid
        self.target = remote.parse(command)
        if not self.target:
            raise InsightError("This pane is not an SSH connection.")
        self.connection = remote.label(self.target)
        self.runner = remote.Runner(self.target)
        self.history = history
        self.lock = threading.Lock()
        self.identity = None
        self.monitor = health.HealthMonitor()
        self.perf = None
        self.perf_cancel = None
        self.last_logs = None
        self.last_inventory = None
        self.last_vulns = None
        self.busy = set()

    # ---------------------------------------------------------- plumbing
    def run_input(self, command: str, stdin: str):
        return self.runner.run_input(command, stdin)

    def _guard(self, job: str):
        with self.lock:
            if job in self.busy:
                raise InsightError(f"{job.capitalize()} is already running for this server.")
            self.busy.add(job)

    def _done(self, job: str):
        with self.lock:
            self.busy.discard(job)

    def _name(self) -> str:
        ident = self.identity
        return ident.hostname if ident and ident.hostname else self.connection

    def _record(self, kind: str, title: str, severity: str, body: str) -> None:
        if self.identity and self.identity.uid:
            try:
                self.history.add(self.identity.uid, kind, title, severity, body, self.connection)
            except OSError:
                pass

    def _fail(self, exc: Exception) -> InsightError:
        if isinstance(exc, InsightError):
            return exc
        return InsightError(remote.explain(str(exc)))

    # ---------------------------------------------------------- identity
    def identify(self, refresh: bool = False) -> dict:
        if self.identity is None or refresh:
            try:
                ident = insight.identify(self.run_input)
                if not ident.uid:
                    # A container, an appliance: nothing it keeps about itself
                    # is unique, so the SSH host key is what it is known by.
                    key = remote.host_key_fingerprint(self.runner)
                    if key:
                        ident.host_key = key
                        ident.uid, ident.source = insight.hostkey_uid(key), "hostkey"
            except Exception as exc:
                raise self._fail(exc)
            if ident.error and not ident.uid:
                raise InsightError(remote.explain(ident.error))
            self.identity = ident
            if ident.uid:
                try:
                    self.history.note_server(ident, self.connection)
                except OSError:
                    pass
        out = plain(self.identity)
        out["source_label"] = insight.ID_SOURCE_LABELS.get(self.identity.source,
                                                            self.identity.source)
        out["connection"] = self.connection
        return out

    # ---------------------------------------------------------- health
    def health(self) -> dict:
        """One reading. The first call takes two, a second apart, because
        every rate -- CPU, network, a process's share -- needs a difference."""
        try:
            sample = self.monitor.step(health.probe(self.run_input))
            if sample is None:
                time.sleep(1.0)
                sample = self.monitor.step(health.probe(self.run_input))
        except Exception as exc:
            raise self._fail(exc)
        levels = health.meter_levels(self.monitor.cfg)
        return {"sample": plain(sample), "history": self.monitor.history[-120:],
                "alerts": plain(self.monitor.alerts[-30:]), "levels": plain(levels),
                "uptime": health.uptime_text(sample.uptime) if sample else ""}

    def stop_process(self, pid: int, force: bool = False) -> dict:
        try:
            command = health.stop_command(pid, force)
        except health.HealthError as exc:
            raise InsightError(str(exc))
        code, out, err = self.run_input(command, "")
        ok = code == 0
        msg = (f"Sent {'KILL' if force else 'TERM'} to {pid}." if ok else
               (err or out or f"exit status {code}").strip().splitlines()[0][:200])
        self._record("action", f"{'Killed' if force else 'Stopped'} process {pid}"
                     if ok else f"Could not stop process {pid}", "info" if ok else "warn", msg)
        return {"ok": ok, "message": msg}

    # ---------------------------------------------------------- performance
    def perf_start(self, mode: str, duration: int = 0, interval: int = 0) -> dict:
        with self.lock:
            if self.perf and self.perf["state"] == "running":
                raise InsightError("A performance check is already running on this server.")
        try:
            samples, every = perfcheck.params(mode, duration, interval)
        except perfcheck.PerfError as exc:
            raise InsightError(str(exc))
        script = perfcheck.sampler_script(samples, every)
        label = (f"{mode} check" if mode != "long"
                 else f"{(samples - 1) * every // 60} min every {every} s")
        run = {"mode": mode, "label": label, "samples": samples, "interval": every,
               "started": time.time(), "state": "running", "report": None, "error": "",
               "diagnosis": "", "text": "", "fallback": None}
        cancel = threading.Event()
        with self.lock:
            self.perf, self.perf_cancel = run, cancel

        def work():
            chunks = []
            try:
                code, err = self.runner.stream_input(
                    "sh -s", script, lambda t: (chunks.append(t), run.update(text="".join(chunks))),
                    cancel, samples * every + 90)
                if not chunks and code not in (0, -1):
                    run["error"] = remote.explain(err or f"exit status {code}")
            except Exception as exc:
                run["error"] = remote.explain(str(exc))
            text = "".join(chunks)
            run["text"] = text
            system = perfcheck.no_proc(text)
            if not system and "TBPH|" not in text and not cancel.is_set() and not run["error"]:
                system = "this server"
            if system:
                # No /proc: a BSD, a Mac, Windows. The one-shot analysis instead.
                try:
                    rep = insight.performance(self.run_input)
                    run["fallback"] = plain(rep) | {"headline": rep.headline(),
                                                     "text": rep.to_text()}
                    run["state"] = "finished"
                    self._record("performance", rep.headline(), rep.severity, rep.to_text())
                except Exception as exc:
                    run.update(state="failed", error=remote.explain(str(exc)))
                return
            try:
                report = perfcheck.report(text, status="finished", mode=mode)
            except Exception as exc:
                report, run["error"] = None, f"the output could not be read: {exc}"
            run["report"] = report
            measured = bool(report and report.get("cpu"))
            run["state"] = "stopped" if cancel.is_set() else "finished" if measured else "failed"
            if measured:
                self._record("performance", perfcheck.headline(report),
                             perfcheck.severity(report), perfcheck.ai_pack(report, self._name()))
        threading.Thread(target=work, name=f"perf-{self.sid}", daemon=True).start()
        return self.perf_status()

    def perf_stop(self) -> dict:
        if self.perf_cancel:
            self.perf_cancel.set()
        return self.perf_status()

    def perf_status(self, tzo: int = 0) -> dict:
        run = self.perf
        if not run:
            return {"state": "none"}
        report = run["report"]
        if run["state"] == "running" and "TBPZ|" in run["text"]:
            try:
                report = perfcheck.report(run["text"], status="running", mode=run["mode"])
            except Exception:
                report = None
        elapsed = time.time() - run["started"]
        total = (run["samples"] - 1) * run["interval"]
        out = {k: run[k] for k in ("mode", "label", "state", "error", "diagnosis", "fallback")}
        out["progress"] = min(1.0, elapsed / total) if total else 1.0
        out["elapsed"] = int(elapsed)
        out["total"] = total
        out["layout"] = (perfcheck.layout(report, tzo, run["diagnosis"],
                                          "AI investigation — Claude")
                         if report and report.get("cpu") else None)
        out["headline"] = perfcheck.headline(report) if report and report.get("cpu") else ""
        return out

    def perf_ai_preview(self) -> str:
        run = self.perf
        if not run or not (run["report"] or {}).get("cpu") or run["state"] == "running":
            raise InsightError("Finish a performance check first; the analysis reads its report.")
        pack = perfcheck.redacted_pack(run["report"], self._name()).strip()
        if len(pack) > MAX_PERF_PACK:
            raise InsightError(f"That analysis pack is {len(pack) // 1024} kB; the limit is "
                               f"{MAX_PERF_PACK // 1024} kB. A shorter check sends a shorter pack.")
        return pack

    def perf_ai(self, payload: str) -> dict:
        if payload != self.perf_ai_preview():
            raise InsightError("The report changed since it was shown; look at it again.")
        self._guard("AI performance analysis")
        try:
            result = agent.analyse(payload, PERF_PROMPT,
                                   label=f"performance analysis of {self._name()}")
        finally:
            self._done("AI performance analysis")
        if not result.get("ok"):
            raise InsightError(result.get("error") or "The analysis failed.")
        answer = result["text"]
        self.perf["diagnosis"] = answer
        title = verdict_line(answer)
        self._record("ai", f"AI: {title[:200]}" if title else "AI performance analysis",
                     perfcheck.severity(self.perf["report"]), answer)
        return {"answer": answer, "usage": result.get("usage")}

    # ---------------------------------------------------------- logs
    def logs(self) -> dict:
        self._guard("log analysis")
        try:
            rep = insight.logs(self.run_input)
        except Exception as exc:
            raise self._fail(exc)
        finally:
            self._done("log analysis")
        self.last_logs = rep
        self._record("logs", rep.headline(), rep.severity, rep.to_text())
        return self._logs_out(rep)

    def _logs_out(self, rep) -> dict:
        return plain(rep) | {"headline": rep.headline(), "summary": rep.summary(),
                             "text": rep.to_text(),
                             "category_labels": insight.CATEGORY_LABELS,
                             "advice": insight.CATEGORY_ADVICE}

    def logs_ai_preview(self) -> dict:
        if self.last_logs is None:
            self.logs()
        rep = self.last_logs
        if not rep.total:
            return {"payload": "", "report": self._logs_out(rep)}
        os_name = self.identity.os_name if self.identity else ""
        excerpt = rep.excerpt(MAX_LOG_EXCERPT - 200).strip()
        head = f"Server operating system: {os_name}\n\n" if os_name else ""
        return {"payload": head + excerpt, "report": self._logs_out(rep)}

    def logs_ai(self, payload: str) -> dict:
        if not payload or payload != self.logs_ai_preview()["payload"]:
            raise InsightError("The logs changed since they were shown; look at them again.")
        self._guard("AI log analysis")
        try:
            result = agent.analyse(payload, LOG_PROMPT, label=f"log analysis of {self._name()}")
        finally:
            self._done("AI log analysis")
        if not result.get("ok"):
            raise InsightError(result.get("error") or "The analysis failed.")
        answer = result["text"]
        title = verdict_line(answer)
        self._record("ai", f"AI: {title[:200]}" if title else "AI log analysis",
                     self.last_logs.severity, answer)
        return {"answer": answer, "usage": result.get("usage")}

    # ---------------------------------------------------------- packages
    def packages(self) -> dict:
        self._guard("package inventory")
        try:
            inv = inventory.inventory(self.run_input)
        except Exception as exc:
            raise self._fail(exc)
        finally:
            self._done("package inventory")
        self.last_inventory = inv
        self._record("inventory", inv.headline(), inv.severity, inv.to_text())
        return plain(inv) | {"headline": inv.headline()}

    # ---------------------------------------------------------- vulnerabilities
    def vulns(self) -> dict:
        """The server's own checks, and what an OSV lookup would send."""
        self._guard("vulnerability scan")
        try:
            if self.last_inventory is None:
                self.last_inventory = inventory.inventory(self.run_input)
            rep = vulnscan.server_checks(self.run_input, self.last_inventory)
        except Exception as exc:
            raise self._fail(exc)
        finally:
            self._done("vulnerability scan")
        self.last_vulns = rep
        inv = self.last_inventory
        eco, wanted = vulnscan.ecosystem(inv), vulnscan.queries(inv)
        out = self._vulns_out(rep)
        out["osv"] = ({"preview": vulnscan.preview(eco, wanted), "packages": len(wanted),
                       "ecosystem": eco} if eco and wanted
                      else {"preview": "", "reason": vulnscan.no_lookup_reason(inv)})
        if not (eco and wanted):
            self._record("vulns", rep.headline(), rep.severity, rep.to_text())
        return out

    def _vulns_out(self, rep) -> dict:
        return plain(rep) | {"headline": rep.headline(), "counts": rep.counts(),
                             "text": rep.to_text()}

    def vulns_lookup(self) -> dict:
        if self.last_vulns is None or self.last_inventory is None:
            raise InsightError("Run the scan first; the lookup uses its package list.")
        self._guard("vulnerability lookup")
        try:
            rep = vulnscan.lookup(self.last_vulns, self.last_inventory)
        finally:
            self._done("vulnerability lookup")
        self._record("vulns", rep.headline(), rep.severity, rep.to_text())
        return self._vulns_out(rep)

    # ---------------------------------------------------------- history
    def server_history(self) -> dict:
        if not self.identity:
            self.identify()
        return {"server": self.history.get(self.identity.uid) if self.identity.uid else None,
                "identity": self.identify()}


class Registry:
    """One Insight per SSH pane, made on first use."""

    def __init__(self, history: ServerHistory):
        self.history = history
        self.items = {}
        self.lock = threading.Lock()

    def get(self, session) -> Insight:
        with self.lock:
            item = self.items.get(session.id)
            if item is None:
                item = self.items[session.id] = Insight(session.id, session.command, self.history)
            return item

    def drop(self, sid: str) -> None:
        with self.lock:
            item = self.items.pop(sid, None)
        if item and item.perf_cancel:
            item.perf_cancel.set()
