import os, sys, tempfile, unittest, threading, subprocess, json
from pathlib import Path
D = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, D)
os.environ.setdefault("HUB_EMBED", "none")
import hub
class T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(__import__("shutil").rmtree, self.tmp)
        hub.DB = os.path.join(self.tmp, "t.db"); self.c = hub.connect(); self.addCleanup(self.c.close)
    def test_home_default_and_db_override(self):
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HUB_HOME=home, HUB_EMBED="none")
            env.pop("HUB_DB", None)
            subprocess.run([sys.executable, os.path.join(D, "hub.py"), "status"], env=env, check=True, capture_output=True)
            self.assertTrue(os.path.isfile(os.path.join(home, "hub.db")))
            override = os.path.join(home, "nested", "custom.db")
            env["HUB_DB"] = override
            subprocess.run([sys.executable, os.path.join(D, "hub.py"), "status"], env=env, check=True, capture_output=True)
            self.assertTrue(os.path.isfile(override))

    def test_brief_uses_bot_env(self):
        env = dict(os.environ, HUB_DB=hub.DB, HUB_BOT="worker", HUB_EMBED="none")
        result = subprocess.run([sys.executable, os.path.join(D, "hub.py"), "--json", "brief"], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["bot"], "worker")

    def test_install_and_config_sources(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "installed hub"
            bins = Path(root) / "bin"
            env = dict(os.environ, HUB_HOME=str(home), HUB_BIN_DIR=str(bins),
                       HUB_DB=str(Path(root) / "database" / "hub.db"), HUB_EMBED="none")
            for key in ("KB_REPOS", "KB_ORG", "KB_DOCS", "KB_SRC", "HUB_KB_CONFIG"):
                env.pop(key, None)
            installer = os.path.join(D, "..", "install.sh")
            def run(*args):
                return subprocess.run(args, env=env, check=True, capture_output=True, text=True)
            run("bash", installer)
            run(str(bins / "hub"), "status")
            doc = Path(root) / "team guide.md"
            doc.write_text("# Team\nCoordination conventions help agents share useful findings and avoid duplicate work.\n")
            config = home / "kb-sources.conf"
            config.write_text("KB_DOCS='" + str(doc) + "'\n")
            run("bash", installer)
            self.assertTrue(config.exists())
            for _ in range(2):
                run("bash", str(home / "kb-sources.sh"))
            sources = json.loads(run(str(bins / "hub"), "--json", "ingest", "--list").stdout)
            self.assertEqual([row["source"] for row in sources], [str(doc)])
            env["KB_DOCS"] = ""
            config.write_text("KB_DOCS='/missing/document'\n")
            run("bash", str(home / "kb-sources.sh"))
            env.pop("HUB_HOME")
            run(str(bins / "hub"), "status")  # symlink resolves installed home

    def test_wal_fts(self):
        self.assertEqual(self.c.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        hub.note_add(self.c, "a", "sample", "fact", "Rust kernel", "wasm modules", "x")
        hits, _ = hub.search(self.c, "wasm", mode="fts"); self.assertEqual(hits[0]["title"], "Rust kernel")
    def test_bad_kind(self):
        with self.assertRaises(ValueError): hub.note_add(self.c, "a", "p", "nope", "t")
    def test_secret_refused(self):
        for s in ["server at " + ".".join(["10", "0", "0", "12"]), "api_key=" + "a" * 20, "ghp_" + "a" * 20]:
            with self.assertRaises(SystemExit): hub.note_add(self.c, "a", "p", "fact", "t", s)
    def test_claim_conflict_and_release(self):
        i = hub.work_claim(self.c, "A", "ui", "Build login")
        with self.assertRaises(RuntimeError): hub.work_claim(self.c, "B", "ui", "build LOGIN")
        with self.assertRaises(RuntimeError): hub.work_update(self.c, i, bot="B", status="done")
        hub.work_update(self.c, i, bot="A", status="done")
        hub.work_claim(self.c, "B", "ui", "Build login")
    def test_concurrent_claims(self):
        res = []
        def go(b):
            c = hub.connect()
            try: hub.work_claim(c, b, "sample", "race"); res.append(b)
            except RuntimeError: pass
            finally: c.close()
        ts = [threading.Thread(target=go, args=(f"b{i}",)) for i in range(8)]; [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(len(res), 1)
    def test_decision_search(self):
        hub.decision_add(self.c, "sample", "Use Cedar policies", "authz", "X", "accepted")
        hits, _ = hub.search(self.c, "Cedar"); self.assertEqual(hits[0]["type"], "decision")
    def test_vector_semantic(self):
        if not (self.c.vec and hub.embedder().model): self.skipTest("vectors unavailable")
        hub.note_add(self.c, "a", "p", "fact", "Database backups run nightly", "")
        hub.note_add(self.c, "a", "p", "fact", "The cat sleeps on the sofa", "")
        hits, mode = hub.search(self.c, "when are snapshots of data taken")
        self.assertEqual(mode, "hybrid"); self.assertIn("backups", hits[0]["title"])
    def test_cli_json(self):
        env = dict(os.environ, HUB_DB=hub.DB, HUB_BOT="tester", HUB_EMBED="none")
        run = lambda *a: json.loads(subprocess.run([os.path.join(D, "hub"), "--json", *a], env=env, capture_output=True, text=True).stdout)
        self.assertIn("id", run("work", "claim", "t1", "--project", "ui"))
        self.assertIn("error", run("work", "claim", "t1", "--project", "ui", "--bot", "other"))
        run("handoff", "add", "reviewer", "please review PR", "--project", "ui")
        self.assertEqual(len(run("handoff", "list", "--to", "reviewer")), 1)
        d = run("decision", "add", "X", "--project", "ui"); run("decision", "set", str(d["id"]), "accepted")
        st = run("status"); self.assertEqual(st["decisions"][0]["status"], "accepted"); self.assertEqual(len(st["work"]), 1)
        self.assertEqual(run("search", "review")["mode"], "fts")
    def test_chunk_by_heading(self):
        ch = hub.chunk_text("# A\nintro text here\n## B\nbody of b\n```\n# not a heading\n```\n# C\nc text")
        self.assertEqual([h for h, _ in ch], ["A", "A > B", "C"]); self.assertIn("# not a heading", ch[1][1])
    def test_ingest_dedupe_redact_rehash(self):
        d = tempfile.mkdtemp(); f = os.path.join(d, "spec.md")
        Path(f).write_text("# Grants\nGrant tokens are verified by the kernel before each call. Host " + ".".join(["10", "1", "2", "3"]) + " api_key=" + "a" * 20 + "\n")
        Path(d, "copy.md").write_text("# Copy\nGrant tokens are verified by the kernel before each call. Host " + ".".join(["10", "1", "2", "3"]) + " api_key=" + "a" * 20 + "\n")
        st = hub.ingest(self.c, d, "sample", url_base="https://github.com/example/sample/blob/main")
        self.assertEqual(st["chunks"], 1)  # duplicate chunk deduped
        body = self.c.execute("SELECT body,url FROM docs").fetchone()
        self.assertNotIn(".".join(["10", "1", "2", "3"]), body[0]); self.assertNotIn("a" * 20, body[0]); self.assertTrue(body[1].startswith("https://github.com/example/sample/blob/main/"))
        self.assertEqual(hub.ingest(self.c, f, "sample")["unchanged"], 1)
        Path(f).write_text(Path(f).read_text() + "\n# Revocation\nRevoked grants are rejected immediately by the runtime guard.\n")
        self.assertEqual(hub.ingest_refresh(self.c)["updated"], 1)
        self.assertEqual(self.c.execute("SELECT count(*) FROM docs WHERE heading='Revocation'").fetchone()[0], 1)
    def test_ask_cites_sources(self):
        f = os.path.join(tempfile.mkdtemp(), "vision.md")
        Path(f).write_text("# Vision\nThe service runs untrusted wasm modules inside a capability sandbox.\n")
        hub.ingest(self.c, f, "sample"); hub.note_add(self.c, "a", "sample", "fact", "Sandbox note", "wasm capability sandbox is mandatory")
        hits, _ = hub.ask(self.c, "wasm sandbox", 5)
        cites = [h["cite"] for h in hits]; self.assertIn(f, cites); self.assertTrue(any(x.startswith("hub note #") for x in cites))
    def test_brief(self):
        hub.work_claim(self.c, "worker", "mcp", "fix audit", "https://github.com/example/mcp/pull/2")
        self.c.execute("INSERT INTO handoffs(created,from_bot,to_bot,project,payload,status) VALUES('x','coordinator','worker','mcp','review skills#5','open')")
        b = hub.brief(self.c, "worker")
        self.assertEqual(len(b["work"]), 1); self.assertEqual(len(b["handoffs_in"]), 1)
        self.assertIn("https://github.com/example/mcp/pull/2", b["prs"]); self.assertIn("skills#5", b["prs"])
        self.assertIn("## Open work", hub.fmt_brief(b))
    def test_cli_ingest_ask_brief(self):
        env = dict(os.environ, HUB_DB=hub.DB, HUB_BOT="tester", HUB_EMBED="none")
        run = lambda *a: json.loads(subprocess.run([os.path.join(D, "hub"), "--json", *a], env=env, capture_output=True, text=True).stdout)
        f = os.path.join(tempfile.mkdtemp(), "x.md"); Path(f).write_text("# Persist\nBackups live in the persistent agent store snapshots.\n")
        self.assertEqual(run("ingest", f, "--project", "general")["chunks"], 1)
        self.assertEqual(run("ask", "where are backups")["results"][0]["cite"], f)
        self.assertEqual(run("brief", "tester")["bot"], "tester")
if __name__ == "__main__": unittest.main(verbosity=2)
