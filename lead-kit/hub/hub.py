#!/usr/bin/env python3
"""Shared knowledge & coordination hub for collaborating agents. Stdlib sqlite3 + optional sqlite-vec/fastembed."""
import argparse, json, os, re, sqlite3, sys, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
HUB_HOME = os.path.expanduser(os.environ.get("HUB_HOME", "~/.local/share/lead-kit/hub"))
DB = os.path.expanduser(os.environ.get("HUB_DB", os.path.join(HUB_HOME, "hub.db")))
NOTE_KINDS = ["fact", "decision", "approach", "lesson", "question", "link"]
WORK_ST = ["planned", "active", "blocked", "done"]
DEC_ST = ["proposed", "accepted", "rejected", "superseded"]
SECRET_RE = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY|\b(?:sk|ghp|gho|xox[abp]|AKIA)[-_A-Za-z0-9]{12,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S{6,})", re.I)
def now(): return datetime.datetime.now().astimezone().isoformat(timespec="seconds")

# ---------- embeddings (pluggable) ----------
class Embedder:
    dim = 384
    def __init__(self):
        self.model = None
        if os.environ.get("HUB_EMBED", "fastembed") == "none": return
        try:
            from fastembed import TextEmbedding
            self.model = TextEmbedding(os.environ.get("HUB_EMBED_MODEL", "BAAI/bge-small-en-v1.5"),
                                       cache_dir=os.path.expanduser(os.environ.get("HUB_MODEL_CACHE", os.path.join(HUB_HOME, ".models"))))
        except Exception: self.model = None
    def embed(self, text):
        return [float(x) for x in next(iter(self.model.embed([text])))] if self.model else None
_EMB = None
def embedder():
    global _EMB
    if _EMB is None: _EMB = Embedder()
    return _EMB

SCHEMA = """
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, created TEXT, author_bot TEXT, project TEXT, kind TEXT, title TEXT, body TEXT, tags TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(title, body, tags, project, content='notes', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS notes_ai AFTER INSERT ON notes BEGIN INSERT INTO notes_fts(rowid,title,body,tags,project) VALUES(new.id,new.title,new.body,new.tags,new.project); END;
CREATE TRIGGER IF NOT EXISTS notes_ad AFTER DELETE ON notes BEGIN INSERT INTO notes_fts(notes_fts,rowid,title,body,tags,project) VALUES('delete',old.id,old.title,old.body,old.tags,old.project); END;
CREATE TABLE IF NOT EXISTS work(id INTEGER PRIMARY KEY, bot TEXT, project TEXT, task TEXT, status TEXT, branch_or_pr TEXT, updated TEXT, notes TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS work_open ON work(project, lower(task)) WHERE status!='done';
CREATE TABLE IF NOT EXISTS handoffs(id INTEGER PRIMARY KEY, created TEXT, from_bot TEXT, to_bot TEXT, project TEXT, payload TEXT, status TEXT DEFAULT 'open');
CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY, project TEXT, title TEXT, status TEXT, rationale TEXT, decided_by TEXT, date TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS decisions_fts USING fts5(title, rationale, project, content='decisions', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS dec_ai AFTER INSERT ON decisions BEGIN INSERT INTO decisions_fts(rowid,title,rationale,project) VALUES(new.id,new.title,new.rationale,new.project); END;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS doc_sources(source TEXT PRIMARY KEY, url TEXT, project TEXT, file_hash TEXT, ingested TEXT, chunks INTEGER);
CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY, source TEXT, url TEXT, project TEXT, heading TEXT, body TEXT, chunk_hash TEXT, idx INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS docs_hash ON docs(chunk_hash);
CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(heading, body, source, project, content='docs', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN INSERT INTO docs_fts(rowid,heading,body,source,project) VALUES(new.id,new.heading,new.body,new.source,new.project); END;
CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON docs BEGIN INSERT INTO docs_fts(docs_fts,rowid,heading,body,source,project) VALUES('delete',old.id,old.heading,old.body,old.source,old.project); END;
"""
class Conn(sqlite3.Connection):
    vec = False

def connect(path=None):
    db_path = path or DB
    if db_path != ":memory:": os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    c = sqlite3.connect(db_path, timeout=30, isolation_level=None, factory=Conn)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA busy_timeout=30000")
    c.executescript(SCHEMA)
    c.vec = False
    if os.environ.get("HUB_EMBED", "fastembed") != "none":
        try:
            import sqlite_vec
            c.enable_load_extension(True); sqlite_vec.load(c); c.enable_load_extension(False)
            c.execute(f"CREATE VIRTUAL TABLE IF NOT EXISTS vec_items USING vec0(key TEXT PRIMARY KEY, embedding float[{Embedder.dim}])")
            c.vec = True
        except Exception: pass
    return c

def check_secret(*texts):
    for t in texts:
        if t and SECRET_RE.search(t):
            sys.exit("refused: text looks like it contains a secret/IP/key. Do NOT store secrets in the hub.")

def index_vec(c, key, text):
    if not c.vec: return
    v = embedder().embed(text)
    if v is None: return
    import sqlite_vec
    c.execute("DELETE FROM vec_items WHERE key=?", (key,))
    c.execute("INSERT INTO vec_items(key, embedding) VALUES(?,?)", (key, sqlite_vec.serialize_float32(v)))

# ---------- operations (also used by tests) ----------
def note_add(c, author, project, kind, title, body="", tags=""):
    if kind not in NOTE_KINDS: raise ValueError(f"kind must be one of {NOTE_KINDS}")
    check_secret(title, body, tags)
    nid = c.execute("INSERT INTO notes(created,author_bot,project,kind,title,body,tags) VALUES(?,?,?,?,?,?,?)",
                    (now(), author, project, kind, title, body, tags)).lastrowid
    index_vec(c, f"note:{nid}", f"{title}\n{body}\n{tags}")
    return nid

def decision_add(c, project, title, rationale="", by="", status="proposed"):
    if status not in DEC_ST: raise ValueError(f"status must be one of {DEC_ST}")
    check_secret(title, rationale)
    did = c.execute("INSERT INTO decisions(project,title,status,rationale,decided_by,date) VALUES(?,?,?,?,?,?)",
                    (project, title, status, rationale, by, now()[:10])).lastrowid
    index_vec(c, f"decision:{did}", f"{title}\n{rationale}")
    return did

def fts_q(q):
    toks = re.findall(r"\w+", q)
    return " OR ".join(f'"{t}"' for t in toks) if toks else '""'

def search(c, q, project=None, limit=10, mode="hybrid", kinds=None):
    """Hybrid: reciprocal-rank fusion of FTS5 BM25 and vector KNN (if available)."""
    ranks = {}
    fq = fts_q(q)
    for tbl, pre in (("notes", "note"), ("decisions", "decision"), ("docs", "doc")):
        rows = c.execute(f"SELECT rowid FROM {tbl}_fts WHERE {tbl}_fts MATCH ? ORDER BY bm25({tbl}_fts) LIMIT 50", (fq,)).fetchall()
        for i, r in enumerate(rows): ranks.setdefault(f"{pre}:{r[0]}", {})["fts"] = i + 1
    used_vec = False
    if mode != "fts" and c.vec:
        v = embedder().embed(q)
        if v is not None:
            import sqlite_vec
            used_vec = True
            rows = c.execute("SELECT key, distance FROM vec_items WHERE embedding MATCH ? AND k=100 ORDER BY distance",
                             (sqlite_vec.serialize_float32(v),)).fetchall()
            for i, r in enumerate(rows): ranks.setdefault(r[0], {})["vec"] = i + 1
    out = []
    for key, rk in ranks.items():
        score = sum(1.0 / (60 + r) for r in rk.values())
        kind, id_ = key.split(":"); id_ = int(id_)
        if kinds and kind not in kinds: continue
        tbl = {"note": "notes", "decision": "decisions", "doc": "docs"}[kind]
        r = c.execute(f"SELECT * FROM {tbl} WHERE id=?", (id_,)).fetchone()
        if not r or (project and r["project"] != project): continue
        d = dict(r); d["type"] = kind
        if kind == "doc": d["title"] = f"{d['source']} § {d['heading']}"
        d["score"] = round(score, 5); d["match"] = sorted(rk)
        out.append(d)
    out.sort(key=lambda d: -d["score"])
    return out[:limit], ("hybrid" if used_vec else "fts")

def work_claim(c, bot, project, task, branch="", notes="", status="active"):
    try:
        return c.execute("INSERT INTO work(bot,project,task,status,branch_or_pr,updated,notes) VALUES(?,?,?,?,?,?,?)",
                         (bot, project, task, status, branch, now(), notes)).lastrowid
    except sqlite3.IntegrityError:
        r = c.execute("SELECT * FROM work WHERE project=? AND lower(task)=lower(?) AND status!='done'", (project, task)).fetchone()
        raise RuntimeError(f"already claimed: work #{r['id']} by {r['bot']} ({r['status']})")

def work_update(c, wid, bot=None, status=None, branch=None, notes=None, force=False):
    r = c.execute("SELECT * FROM work WHERE id=?", (wid,)).fetchone()
    if not r: raise RuntimeError(f"no work #{wid}")
    if bot and r["bot"] != bot and not force: raise RuntimeError(f"work #{wid} belongs to {r['bot']} (use --force)")
    if status and status not in WORK_ST: raise ValueError(f"status must be one of {WORK_ST}")
    c.execute("UPDATE work SET status=coalesce(?,status), branch_or_pr=coalesce(?,branch_or_pr), notes=coalesce(?,notes), updated=? WHERE id=?",
              (status, branch, notes, now(), wid))


# ---------- document knowledge base ----------
import hashlib, urllib.request
DOC_EXT = (".md", ".markdown", ".txt", ".rst")
SKIP_DIRS = {".git", "node_modules", "target", ".venv", "__pycache__", "dist", ".next"}
REDACT_RE = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----|\b(?:sk|ghp|gho|github_pat|xox[abp]|AKIA)[-_A-Za-z0-9]{12,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S{6,})", re.I | re.S)
def redact(t): return REDACT_RE.sub("<redacted>", t)
def read_text(p, errors="strict"):
    with open(p, encoding="utf-8", errors=errors) as fh: return fh.read()
def sha(t): return hashlib.sha256(t.encode()).hexdigest()

def chunk_text(text, max_chars=1800):
    """Split markdown by headings; long sections split on paragraphs. Returns [(heading_path, body)]."""
    out, path, buf = [], [], []
    def flush():
        body = "\n".join(buf).strip()
        if body:
            h = " > ".join(path) or "(top)"
            parts, cur = [], ""
            for para in re.split(r"\n\s*\n", body):
                if cur and len(cur) + len(para) > max_chars: parts.append(cur); cur = ""
                cur = (cur + "\n\n" + para) if cur else para
            if cur: parts.append(cur)
            out.extend((h, p) for p in parts)
        buf.clear()
    fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"): fence = not fence
        m = None if fence else re.match(r"^(#{1,6})\s+(.*)", line)
        if m:
            flush(); lvl = len(m.group(1)); del path[lvl - 1:]
            while len(path) < lvl - 1: path.append("")
            path.append(m.group(2).strip())
        else: buf.append(line)
    flush()
    return [(" > ".join(x for x in h.split(" > ") if x) or "(top)", b) for h, b in out]

def ingest_text(c, source, text, project="general", url=None, force=False):
    """Ingest one document. Skips if unchanged (file hash). Returns number of chunks stored (-1 = unchanged)."""
    fh = sha(text)
    old = c.execute("SELECT file_hash FROM doc_sources WHERE source=?", (source,)).fetchone()
    if old and old["file_hash"] == fh and not force: return -1
    text = redact(text)
    for r in c.execute("SELECT id FROM docs WHERE source=?", (source,)).fetchall():
        if c.vec: c.execute("DELETE FROM vec_items WHERE key=?", (f"doc:{r['id']}",))
    c.execute("DELETE FROM docs WHERE source=?", (source,))
    n = 0
    for i, (h, body) in enumerate(chunk_text(text)):
        if len(body) < 40: continue
        ch = sha(re.sub(r"\s+", " ", body).strip().lower())
        if c.execute("SELECT 1 FROM docs WHERE chunk_hash=?", (ch,)).fetchone(): continue  # dedupe across sources
        did = c.execute("INSERT INTO docs(source,url,project,heading,body,chunk_hash,idx) VALUES(?,?,?,?,?,?,?)",
                        (source, url, project, h, body, ch, i)).lastrowid
        index_vec(c, f"doc:{did}", f"{h}\n{body}"); n += 1
    c.execute("INSERT OR REPLACE INTO doc_sources(source,url,project,file_hash,ingested,chunks) VALUES(?,?,?,?,?,?)",
              (source, url, project, fh, now(), n))
    return n

def ingest(c, target, project="general", url_base=None, force=False):
    """Ingest a file, a directory (recursively, text/markdown only) or an http(s) URL. Returns stats dict."""
    st = {"files": 0, "chunks": 0, "unchanged": 0}
    def one(src, text, url):
        n = ingest_text(c, src, text, project, url, force); st["files"] += 1
        if n < 0: st["unchanged"] += 1
        else: st["chunks"] += n
    if re.match(r"https?://", target):
        with urllib.request.urlopen(target, timeout=30) as r: one(target, r.read().decode("utf-8", "replace"), target)
        return st
    target = os.path.abspath(target)
    files = [target]
    if os.path.isdir(target):
        files = []
        for d, ds, fs in os.walk(target):
            ds[:] = [x for x in ds if x not in SKIP_DIRS]
            files += [os.path.join(d, f) for f in fs if f.lower().endswith(DOC_EXT)]
    for f in sorted(files):
        try: text = read_text(f)
        except (UnicodeDecodeError, OSError): continue
        url = None
        if url_base:
            root = target if os.path.isdir(target) else os.path.dirname(target)
            url = url_base.rstrip("/") + "/" + os.path.relpath(f, root)
        one(f, text, url)
    return st

def ingest_refresh(c):
    """Re-ingest every known local source whose content changed; drop sources whose file vanished."""
    st = {"checked": 0, "updated": 0, "missing": 0}
    for r in c.execute("SELECT * FROM doc_sources").fetchall():
        st["checked"] += 1
        if re.match(r"https?://", r["source"]): continue
        if not os.path.exists(r["source"]): st["missing"] += 1; continue
        n = ingest_text(c, r["source"], read_text(r["source"], "replace"), r["project"], r["url"])
        if n >= 0: st["updated"] += 1
    return st

def ask(c, q, k=5, project=None):
    hits, mode = search(c, q, project, k, "hybrid")
    for h in hits:
        if h["type"] == "doc": h["cite"] = h.get("url") or h["source"]; h["snippet"] = h["body"][:400]
        elif h["type"] == "note": h["cite"] = f"hub note #{h['id']}"; h["snippet"] = (h.get("body") or "")[:400]
        else: h["cite"] = f"hub decision #{h['id']}"; h["snippet"] = (h.get("rationale") or "")[:400]
    return hits, mode

PR_RE = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/pull/\d+|\b[\w.-]+#\d+\b")
def brief(c, bot, days=7):
    like = f"%{bot}%"
    work = rows(c, "SELECT * FROM work WHERE bot LIKE ? AND status!='done' ORDER BY updated DESC", (like,))
    ho_in = rows(c, "SELECT * FROM handoffs WHERE status='open' AND to_bot LIKE ? ORDER BY id DESC", (like,))
    ho_out = rows(c, "SELECT * FROM handoffs WHERE status='open' AND from_bot LIKE ? ORDER BY id DESC", (like,))
    since = (datetime.datetime.now().astimezone() - datetime.timedelta(days=days)).isoformat(timespec="seconds")
    decs = rows(c, "SELECT * FROM decisions WHERE decided_by LIKE ? OR status='proposed' ORDER BY id DESC LIMIT 10", (like,))
    notes = rows(c, "SELECT * FROM notes WHERE author_bot LIKE ? AND created>=? ORDER BY id DESC LIMIT 10", (like, since))
    prs = []
    for t in [w.get("branch_or_pr") or "" for w in work] + [w.get("notes") or "" for w in work] + \
             [n["title"] + " " + n["body"] for n in notes] + [h["payload"] for h in ho_in + ho_out]:
        for m in PR_RE.findall(t):
            if m not in prs: prs.append(m)
    return {"bot": bot, "work": work, "handoffs_in": ho_in, "handoffs_out": ho_out, "decisions": decs, "notes": notes, "prs": prs}

def fmt_brief(b):
    t = [f"# Brief: {b['bot']}  ({now()})", "## Open work"]
    t += [f"- #{w['id']} {w['status']} ({w['project']}) {w['task']} {w['branch_or_pr'] or ''}" for w in b["work"]] or ["- (none)"]
    t.append("## Handoffs to you"); t += [f"- #{h['id']} from {h['from_bot']} ({h['project']}): {h['payload'][:160]}" for h in b["handoffs_in"]] or ["- (none)"]
    t.append("## Handoffs you gave (open)"); t += [f"- #{h['id']} to {h['to_bot']}: {h['payload'][:120]}" for h in b["handoffs_out"]] or ["- (none)"]
    t.append("## PRs mentioned"); t += [f"- {p}" for p in b["prs"]] or ["- (none)"]
    t.append("## Decisions (yours or proposed)"); t += [f"- #{d['id']} {d['status']} ({d['project']}) {d['title']}" for d in b["decisions"]] or ["- (none)"]
    t.append("## Your recent notes"); t += [f"- #{n['id']} [{n['kind']}] ({n['project']}) {n['title']}" for n in b["notes"]] or ["- (none)"]
    return "\n".join(t)

# ---------- output ----------
def emit(args, data, text):
    if args.json: print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else: print(text if text else "(nothing)")
def rows(c, sql, p=()): return [dict(r) for r in c.execute(sql, p).fetchall()]
def bot_default(a): return a or os.environ.get("HUB_BOT") or sys.exit("--bot required (or set HUB_BOT)")

def main(argv=None):
    p = argparse.ArgumentParser(prog="hub", description="Shared bot knowledge & coordination hub")
    p.add_argument("--json", action="store_true")
    sp = p.add_subparsers(dest="cmd", required=True)
    n = sp.add_parser("note").add_subparsers(dest="sub", required=True)
    x = n.add_parser("add"); x.add_argument("title"); x.add_argument("--body", default=""); x.add_argument("--project", default="general")
    x.add_argument("--kind", default="fact", choices=NOTE_KINDS); x.add_argument("--tags", default=""); x.add_argument("--bot")
    x = n.add_parser("search"); x.add_argument("query"); x.add_argument("--project"); x.add_argument("--limit", type=int, default=10)
    x = n.add_parser("show"); x.add_argument("id", type=int)
    x = n.add_parser("list"); x.add_argument("--project"); x.add_argument("--limit", type=int, default=20)
    w = sp.add_parser("work").add_subparsers(dest="sub", required=True)
    x = w.add_parser("claim"); x.add_argument("task"); x.add_argument("--project", required=True); x.add_argument("--bot")
    x.add_argument("--branch", default=""); x.add_argument("--notes", default=""); x.add_argument("--status", default="active", choices=["planned", "active"])
    x = w.add_parser("update"); x.add_argument("id", type=int); x.add_argument("--status", choices=WORK_ST); x.add_argument("--branch")
    x.add_argument("--notes"); x.add_argument("--bot"); x.add_argument("--force", action="store_true")
    x = w.add_parser("release"); x.add_argument("id", type=int); x.add_argument("--bot"); x.add_argument("--notes"); x.add_argument("--force", action="store_true")
    x = w.add_parser("list"); x.add_argument("--project"); x.add_argument("--active", action="store_true"); x.add_argument("--bot")
    h = sp.add_parser("handoff").add_subparsers(dest="sub", required=True)
    x = h.add_parser("add"); x.add_argument("to_bot"); x.add_argument("payload"); x.add_argument("--project", default="general"); x.add_argument("--bot")
    x = h.add_parser("list"); x.add_argument("--to"); x.add_argument("--all", action="store_true")
    x = h.add_parser("done"); x.add_argument("id", type=int)
    d = sp.add_parser("decision").add_subparsers(dest="sub", required=True)
    x = d.add_parser("add"); x.add_argument("title"); x.add_argument("--project", required=True); x.add_argument("--rationale", default="")
    x.add_argument("--status", default="proposed", choices=DEC_ST); x.add_argument("--bot")
    x = d.add_parser("list"); x.add_argument("--project"); x.add_argument("--status", choices=DEC_ST)
    x = d.add_parser("set"); x.add_argument("id", type=int); x.add_argument("status", choices=DEC_ST); x.add_argument("--bot")
    sp.add_parser("status")
    x = sp.add_parser("search"); x.add_argument("query"); x.add_argument("--project"); x.add_argument("--limit", type=int, default=10)
    x.add_argument("--fts", action="store_true", help="keyword only")
    sp.add_parser("reindex", help="(re)embed all notes, decisions and docs")
    x = sp.add_parser("ingest", help="ingest docs (file, dir or URL); unchanged files are skipped by hash")
    x.add_argument("target", nargs="?"); x.add_argument("--project", default="general"); x.add_argument("--url-base")
    x.add_argument("--force", action="store_true"); x.add_argument("--refresh", action="store_true", help="re-ingest all known changed sources")
    x.add_argument("--list", action="store_true", help="list ingested sources")
    x = sp.add_parser("ask", help="hybrid FTS+vector answer sources with citations"); x.add_argument("question")
    x.add_argument("-k", type=int, default=5); x.add_argument("--project")
    x = sp.add_parser("brief", help="one-page current state for a bot"); x.add_argument("bot", nargs="?"); x.add_argument("--days", type=int, default=7)
    a = p.parse_args(argv)
    c = connect()
    try:
        return dispatch(c, a)
    except (RuntimeError, ValueError) as e:
        if a.json: print(json.dumps({"error": str(e)}))
        else: print(f"error: {e}", file=sys.stderr)
        return 1

def fmt_hits(hits):
    return "\n".join(f"[{h['type']} #{h['id']}] ({h['project']}) {h['title']}  score={h['score']} via {'+'.join(h['match'])}" for h in hits)

def dispatch(c, a):
    cmd, sub = a.cmd, getattr(a, "sub", None)
    if cmd == "note":
        if sub == "add":
            i = note_add(c, bot_default(a.bot), a.project, a.kind, a.title, a.body, a.tags); emit(a, {"id": i}, f"note #{i} added")
        elif sub in ("search",):
            hits, mode = search(c, a.query, a.project, a.limit); hits = [h for h in hits if h["type"] == "note"]
            emit(a, {"mode": mode, "results": hits}, fmt_hits(hits))
        elif sub == "show":
            r = c.execute("SELECT * FROM notes WHERE id=?", (a.id,)).fetchone()
            if not r: raise RuntimeError(f"no note #{a.id}")
            r = dict(r); emit(a, r, f"#{r['id']} [{r['kind']}] {r['title']}\nproject={r['project']} by={r['author_bot']} at={r['created']} tags={r['tags']}\n\n{r['body']}")
        elif sub == "list":
            q, pp = "SELECT * FROM notes", []
            if a.project: q += " WHERE project=?"; pp.append(a.project)
            rs = rows(c, q + " ORDER BY id DESC LIMIT ?", pp + [a.limit])
            emit(a, rs, "\n".join(f"#{r['id']} [{r['kind']}] ({r['project']}) {r['title']}" for r in rs))
    elif cmd == "work":
        if sub == "claim":
            i = work_claim(c, bot_default(a.bot), a.project, a.task, a.branch, a.notes, a.status); emit(a, {"id": i}, f"claimed work #{i}")
        elif sub == "update":
            work_update(c, a.id, a.bot or os.environ.get("HUB_BOT"), a.status, a.branch, a.notes, a.force); emit(a, {"id": a.id, "ok": True}, f"work #{a.id} updated")
        elif sub == "release":
            work_update(c, a.id, a.bot or os.environ.get("HUB_BOT"), "done", None, a.notes, a.force); emit(a, {"id": a.id, "ok": True}, f"work #{a.id} released (done)")
        elif sub == "list":
            q, pp = "SELECT * FROM work WHERE 1=1", []
            if a.project: q += " AND project=?"; pp.append(a.project)
            if a.bot: q += " AND bot=?"; pp.append(a.bot)
            if a.active: q += " AND status IN ('active','blocked','planned')"
            rs = rows(c, q + " ORDER BY updated DESC", pp)
            emit(a, rs, "\n".join(f"#{r['id']} {r['status']:8} {r['bot']:16} ({r['project']}) {r['task']} {r['branch_or_pr'] or ''}" for r in rs))
    elif cmd == "handoff":
        if sub == "add":
            check_secret(a.payload)
            i = c.execute("INSERT INTO handoffs(created,from_bot,to_bot,project,payload,status) VALUES(?,?,?,?,?,'open')",
                          (now(), bot_default(a.bot), a.to_bot, a.project, a.payload)).lastrowid
            emit(a, {"id": i}, f"handoff #{i} -> {a.to_bot}")
        elif sub == "list":
            q, pp = "SELECT * FROM handoffs WHERE 1=1", []
            if not a.all: q += " AND status='open'"
            if a.to: q += " AND to_bot=?"; pp.append(a.to)
            rs = rows(c, q + " ORDER BY id DESC", pp)
            emit(a, rs, "\n".join(f"#{r['id']} {r['status']} {r['from_bot']} -> {r['to_bot']} ({r['project']}): {r['payload']}" for r in rs))
        elif sub == "done":
            if not c.execute("UPDATE handoffs SET status='done' WHERE id=?", (a.id,)).rowcount: raise RuntimeError(f"no handoff #{a.id}")
            emit(a, {"id": a.id, "ok": True}, f"handoff #{a.id} done")
    elif cmd == "decision":
        if sub == "add":
            i = decision_add(c, a.project, a.title, a.rationale, bot_default(a.bot), a.status); emit(a, {"id": i}, f"decision #{i} added")
        elif sub == "list":
            q, pp = "SELECT * FROM decisions WHERE 1=1", []
            if a.project: q += " AND project=?"; pp.append(a.project)
            if a.status: q += " AND status=?"; pp.append(a.status)
            rs = rows(c, q + " ORDER BY id DESC", pp)
            emit(a, rs, "\n".join(f"#{r['id']} {r['status']:10} ({r['project']}) {r['title']} [{r['decided_by']} {r['date']}]" for r in rs))
        elif sub == "set":
            if not c.execute("UPDATE decisions SET status=?, date=?, decided_by=coalesce(?,decided_by) WHERE id=?",
                             (a.status, now()[:10], a.bot or os.environ.get("HUB_BOT"), a.id)).rowcount: raise RuntimeError(f"no decision #{a.id}")
            emit(a, {"id": a.id, "status": a.status}, f"decision #{a.id} -> {a.status}")
    elif cmd == "status":
        work = rows(c, "SELECT * FROM work WHERE status!='done' ORDER BY bot, updated DESC")
        decs = rows(c, "SELECT * FROM decisions ORDER BY date DESC, id DESC LIMIT 8")
        hos = rows(c, "SELECT * FROM handoffs WHERE status='open' ORDER BY id DESC")
        vec = "on" if (c.vec and embedder().model) else "off (FTS5 only)"
        t = [f"== Active work ==  (vector search: {vec})"]
        cur = None
        for r in work:
            if r["bot"] != cur: cur = r["bot"]; t.append(f"{cur}:")
            t.append(f"  #{r['id']} {r['status']:8} ({r['project']}) {r['task']} {r['branch_or_pr'] or ''}")
        if not work: t.append("  (none)")
        t.append("== Open handoffs ==")
        t += [f"  #{r['id']} {r['from_bot']} -> {r['to_bot']} ({r['project']}): {r['payload'][:80]}" for r in hos] or ["  (none)"]
        t.append("== Recent decisions ==")
        t += [f"  #{r['id']} {r['status']:10} ({r['project']}) {r['title']}" for r in decs] or ["  (none)"]
        emit(a, {"work": work, "handoffs": hos, "decisions": decs, "vector": vec}, "\n".join(t))
    elif cmd == "search":
        hits, mode = search(c, a.query, a.project, a.limit, "fts" if a.fts else "hybrid")
        emit(a, {"mode": mode, "results": hits}, f"mode: {mode}\n" + fmt_hits(hits))
    elif cmd == "reindex":
        n = 0
        for r in c.execute("SELECT * FROM notes").fetchall(): index_vec(c, f"note:{r['id']}", f"{r['title']}\n{r['body']}\n{r['tags']}"); n += 1
        for r in c.execute("SELECT * FROM decisions").fetchall(): index_vec(c, f"decision:{r['id']}", f"{r['title']}\n{r['rationale']}"); n += 1
        for r in c.execute("SELECT * FROM docs").fetchall(): index_vec(c, f"doc:{r['id']}", f"{r['heading']}\n{r['body']}"); n += 1
        emit(a, {"indexed": n, "vec": c.vec}, f"reindexed {n} items (vec={'on' if c.vec else 'off'})")
    elif cmd == "ingest":
        if a.list:
            rs = rows(c, "SELECT source,url,project,chunks,ingested FROM doc_sources ORDER BY source")
            emit(a, rs, "\n".join(f"{r['chunks']:4} ({r['project']}) {r['url'] or r['source']}" for r in rs))
        elif a.refresh or not a.target:
            st = ingest_refresh(c); emit(a, st, f"refresh: {st}")
        else:
            st = ingest(c, a.target, a.project, a.url_base, a.force); emit(a, st, f"ingested: {st}")
    elif cmd == "ask":
        hits, mode = ask(c, a.question, a.k, a.project)
        txt = [f"mode: {mode}"]
        for i, h in enumerate(hits, 1):
            txt.append(f"[{i}] {h['title']}\n    source: {h['cite']}\n    {' '.join(h['snippet'].split())[:300]}")
        emit(a, {"mode": mode, "results": [{k: h.get(k) for k in ("type", "id", "title", "cite", "snippet", "score", "project")} for h in hits]}, "\n".join(txt))
    elif cmd == "brief":
        b = brief(c, bot_default(a.bot), a.days); emit(a, b, fmt_brief(b))
    return 0

if __name__ == "__main__":
    sys.exit(main())
