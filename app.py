# app.py
# Safe Python Command Terminal (MVP) — extended with extra safe commands + portable stat
import shlex
import subprocess
import os
import shutil
import time
import hashlib
import re
from pathlib import Path
from typing import Dict, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from threading import Lock

# optional psutil import — fallback if not available
try:
    import psutil
    _HAS_PSUTIL = True
except Exception:
    psutil = None
    _HAS_PSUTIL = False

app = FastAPI(title="Safe Python Command Terminal (MVP)")

# Limit operations to a sandbox directory inside project
ROOT = Path.cwd() / "sandbox"
ROOT.mkdir(exist_ok=True)

# Current working directory (starts at ROOT). Protected by lock for thread-safety.
CURRENT_DIR = ROOT.resolve()
_dir_lock = Lock()

# Process tracking for kill support
PROCESS_LOCK = Lock()
CURRENT_PROCESS = None  # will hold subprocess.Popen while a command is running

# Whitelist (extended)
WHITELIST = {
    "ls", "dir", "pwd", "cat", "type", "read", "echo", "mkdir", "rmdir", "touch", "stat",
    "whoami", "uname", "df", "du", "ps", "stats", "help",
    "cd", "write", "append", "rm", "mv", "cp", "restore", "empty-trash",
    "head", "tail", "grep", "find", "tree", "wc", "md5", "sha256"
}

MAX_OUTPUT_CHARS = 20000
TIMEOUT = 7  # seconds


def safe_path(path_str: str, base_dir: Optional[Path] = None) -> Path:
    base = (base_dir or CURRENT_DIR).resolve()
    p = Path(path_str)
    if p.is_absolute():
        # Map absolute into sandbox root to avoid escapes
        try:
            candidate = (ROOT / p.relative_to(p.anchor)).resolve()
        except Exception:
            candidate = (ROOT / p.name).resolve()
    else:
        candidate = (base / p).resolve()
    try:
        if not str(candidate).startswith(str(ROOT.resolve())):
            candidate = (ROOT / Path(path_str).name).resolve()
    except Exception:
        candidate = (ROOT / Path(path_str).name).resolve()
    return candidate


def get_system_stats() -> str:
    """
    Return a friendly CPU / memory summary and a small list of top CPU-consuming processes.
    Uses a short two-sample approach to get reliable per-process cpu_percent values.
    """
    try:
        # cpu overall (sample briefly)
        cpu_total = psutil.cpu_percent(interval=0.25)

        mem = psutil.virtual_memory()

        # collect process objects snapshot
        procs = []
        for p in psutil.process_iter(['pid', 'name']):
            procs.append(p)

        # initialize cpu_percent measurement for each process (first call seeds internal counters)
        for p in procs:
            try:
                p.cpu_percent(None)
            except Exception:
                # ignore processes we can't query
                pass

        # short sleep to allow cpu_percent to be measured over an interval
        time.sleep(0.12)

        # now read cpu_percent and memory_percent
        procs_info = []
        for p in procs:
            try:
                info = p.as_dict(attrs=['pid', 'name'], ad_value="")
                cpu_p = p.cpu_percent(None) or 0.0
                mem_p = p.memory_percent() or 0.0
                # normalize long names
                name = (info.get('name') or "")[:20]
                procs_info.append({"pid": info.get('pid'), "name": name, "cpu": float(cpu_p), "mem": float(mem_p)})
            except Exception:
                # best-effort: skip processes we cannot inspect
                continue

        # sort by cpu desc and take top N
        procs_sorted = sorted(procs_info, key=lambda x: x.get('cpu', 0.0), reverse=True)[:6]

        top_procs_lines = []
        for pi in procs_sorted:
            pid = pi.get('pid', 0)
            name = (pi.get('name') or "")[:20]
            cpu_p = pi.get('cpu', 0.0)
            mem_p = pi.get('mem', 0.0)
            top_procs_lines.append(f"{pid:6} {name:20} cpu={cpu_p:5.1f}% mem={mem_p:5.1f}%")

        procs_text = "\n".join(top_procs_lines) if top_procs_lines else "No process info available (permission)."

        return f"CPU: {cpu_total:.1f}%\nMemory: {mem.percent:.1f}% ({int(mem.used/1024**2)}MB used of {int(mem.total/1024**2)}MB)\n\nTop processes:\n{procs_text}"

    except Exception:
        # fallback minimal info if psutil can't be used
        import platform
        try:
            return f"psutil error — fallback info: {platform.system()} {platform.release()}"
        except Exception:
            return "psutil not available and fallback failed."


def windows_translate(parts: list) -> list:
    base = parts[0].lower()
    args = parts[1:]
    def sp(p): return str(p)
    if base in ("ls", "dir"):
        ps = ["powershell", "-NoProfile", "-Command", "Get-ChildItem", "-Force", "-Name"]
        if args:
            ps.append("--%"); ps += [sp(a) for a in args]
        return ps
    if base in ("cat", "type", "read"):
        if not args:
            return ["powershell", "-NoProfile", "-Command", "Write-Output", "'Error: missing filename'"]
        files = [sp(a) for a in args]
        return ["powershell", "-NoProfile", "-Command", "Get-Content", "-Raw"] + files
    if base == "mkdir":
        if not args:
            return ["powershell", "-NoProfile", "-Command", "Write-Output", "'Error: missing directory name'"]
        cmd = " ; ".join([f"New-Item -ItemType Directory -Force -Path '{sp(a)}'" for a in args])
        return ["powershell", "-NoProfile", "-Command", cmd]
    if base == "rmdir":
        if not args:
            return ["powershell", "-NoProfile", "-Command", "Write-Output", "'Error: missing directory name'"]
        cmd = " ; ".join([f"Remove-Item -Recurse -Force '{sp(a)}'" for a in args])
        return ["powershell", "-NoProfile", "-Command", cmd]
    if base == "echo":
        text = " ".join(args) if args else ""
        return ["powershell", "-NoProfile", "-Command", "Write-Output", text]
    if base == "pwd":
        return ["powershell", "-NoProfile", "-Command", "Write-Output", str(CURRENT_DIR)]
    fallback = [parts[0]] + [sp(a) for a in args]
    return fallback


def _move_to_trash(target: Path) -> str:
    trash = ROOT / ".trash"
    trash.mkdir(exist_ok=True)
    name = target.name
    dest = trash / name
    if dest.exists():
        base = dest.stem; suf = dest.suffix; i = 1
        while True:
            newname = f"{base}_{i}{suf}"
            dest = trash / newname
            if not dest.exists():
                break
            i += 1
    try:
        # use replace to move atomically when possible
        target.replace(dest)
        return f"Moved to trash: {target.name} -> {dest.name}"
    except Exception:
        # fallback to shutil.move
        try:
            shutil.move(str(target), str(dest))
            return f"Moved to trash: {target.name} -> {dest.name}"
        except Exception as e:
            return f"{target.name}: move to trash failed: {e}"


def _spawn_and_wait(args, cwd: Path) -> Dict:
    global CURRENT_PROCESS
    proc = None
    try:
        with PROCESS_LOCK:
            proc = subprocess.Popen(args, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            CURRENT_PROCESS = proc
        try:
            out, err = proc.communicate(timeout=TIMEOUT)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            with PROCESS_LOCK:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                out, err = proc.communicate(timeout=2)
            except Exception:
                out, err = "", "Process killed due to timeout."
            rc = -1
        return {"ok": rc == 0, "stdout": (out or ""), "stderr": (err or ""), "rc": rc}
    finally:
        with PROCESS_LOCK:
            CURRENT_PROCESS = None


def _safe_mv(src: Path, dest: Path) -> str:
    try:
        dest_parent = dest.parent
        dest_parent.mkdir(parents=True, exist_ok=True)
        # if dest is an existing directory, move src into it
        if dest.exists() and dest.is_dir():
            final = dest / src.name
        else:
            final = dest
        shutil.move(str(src), str(final))
        return f"Moved: {src.name} -> {final}"
    except Exception as e:
        return f"Move failed: {e}"


def _safe_cp(src: Path, dest: Path, recursive: bool = False) -> str:
    try:
        if src.is_dir():
            if not recursive:
                return "Source is a directory; use cp -r to copy directories"
            # if dest exists and is dir, copy into it
            if dest.exists() and dest.is_dir():
                final = dest / src.name
            else:
                final = dest
            if final.exists():
                return f"Destination already exists: {final}"
            shutil.copytree(str(src), str(final))
            return f"Directory copied: {src.name} -> {final}"
        else:
            dest_parent = dest if dest.is_dir() else dest.parent
            dest_parent.mkdir(parents=True, exist_ok=True)
            final = dest if not dest.is_dir() and dest.suffix else (dest_parent / src.name if dest.is_dir() else dest)
            shutil.copy2(str(src), str(final))
            return f"Copied: {src.name} -> {final}"
    except Exception as e:
        return f"Copy failed: {e}"


def _restore_from_trash(name: str, target_dir: Path) -> str:
    trash = ROOT / ".trash"
    src = trash / name
    if not src.exists():
        return f"{name}: not found in trash"
    # choose destination name and avoid collision
    dest = target_dir / name
    if dest.exists():
        base = dest.stem; suf = dest.suffix; i = 1
        while True:
            candidate = target_dir / f"{base}_restored_{i}{suf}"
            if not candidate.exists():
                dest = candidate
                break
            i += 1
    try:
        shutil.move(str(src), str(dest))
        return f"Restored: {name} -> {dest.name}"
    except Exception as e:
        return f"Restore failed: {e}"


# --- Extra helpers for new commands ---
def _read_file_lines(path: Path, max_lines: Optional[int] = None):
    try:
        text = path.read_text(encoding="utf8", errors="replace")
        lines = text.splitlines()
        if max_lines is not None:
            return lines[:max_lines]
        return lines
    except Exception as e:
        raise


def _tail_file_lines(path: Path, n: int = 10):
    try:
        text = path.read_text(encoding="utf8", errors="replace")
        lines = text.splitlines()
        return lines[-n:]
    except Exception as e:
        raise


def _grep_in_file(path: Path, pattern: str, ignore_case: bool = False, use_regex: bool = False):
    out = []
    flags = re.IGNORECASE if ignore_case else 0
    try:
        with path.open('r', encoding='utf8', errors='replace') as fh:
            for i, ln in enumerate(fh, start=1):
                hay = ln.rstrip("\n")
                matched = False
                if use_regex:
                    try:
                        if re.search(pattern, hay, flags):
                            matched = True
                    except re.error:
                        # fall back to substring if regex bad
                        if (pattern.lower() in hay.lower()) if ignore_case else (pattern in hay):
                            matched = True
                else:
                    if ignore_case:
                        if pattern.lower() in hay.lower():
                            matched = True
                    else:
                        if pattern in hay:
                            matched = True
                if matched:
                    out.append(f"{i}:{hay}")
        return out
    except Exception:
        return []


def _compute_hash(path: Path, algo: str = "sha256"):
    try:
        h = hashlib.new(algo)
    except Exception:
        return None
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _tree_listing(start: Path, max_depth: int = 3):
    out = []
    start = start.resolve()
    def _walk(p: Path, depth=0):
        if depth > max_depth:
            return
        try:
            for entry in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                prefix = "  " * depth + ("└─ " if depth else "")
                out.append(prefix + entry.name + ("/" if entry.is_dir() else ""))
                if entry.is_dir():
                    _walk(entry, depth + 1)
        except Exception:
            out.append("  " * depth + "[permission denied or unreadable]")
    _walk(start, 0)
    return out


def _wc_counts(path: Path):
    try:
        text = path.read_text(encoding="utf8", errors="replace")
        lines = text.splitlines()
        words = sum(len(l.split()) for l in lines)
        chars = len(text)
        return {"lines": len(lines), "words": words, "chars": chars}
    except Exception:
        return None


# ---- Core command runner ----
def run_whitelisted_command(cmd: str) -> Dict:
    global CURRENT_DIR
    try:
        parts = shlex.split(cmd, posix=not os.name == "nt")
        if len(parts) == 0:
            return {"ok": False, "stderr": "Empty command."}
        base = parts[0].lower()
        if base not in WHITELIST:
            return {"ok": False, "stderr": f"Command '{base}' not allowed."}

        # help
        if base == "help":
            return {"ok": True, "stdout": "Allowed commands: " + ", ".join(sorted(WHITELIST))}

        # stats
        if base in ("ps", "stats"):
            try:
                s = get_system_stats()
                return {"ok": True, "stdout": s}
            except Exception as e:
                return {"ok": False, "stderr": f"Could not retrieve stats: {e}"}

        # cd
        if base == "cd":
            target = parts[1] if len(parts) > 1 else "."
            with _dir_lock:
                newp = safe_path(target, base_dir=CURRENT_DIR)
                if newp.exists() and newp.is_dir():
                    CURRENT_DIR = newp
                    return {"ok": True, "stdout": str(CURRENT_DIR)}
                else:
                    return {"ok": False, "stderr": f"Directory not found: {newp}"}

        # pwd
        if base == "pwd":
            return {"ok": True, "stdout": str(CURRENT_DIR)}

        # stat  (portable, uses Python Path.stat)
        if base == "stat":
            # usage: stat <filename>
            if len(parts) < 2:
                return {"ok": False, "stderr": "stat requires a filename: stat file.txt"}
            target = safe_path(parts[1], base_dir=CURRENT_DIR)
            if not target.exists():
                return {"ok": False, "stderr": f"File not found: {parts[1]}"}
            try:
                st = target.stat()
                is_dir = target.is_dir()
                size = st.st_size
                mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                atime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime))
                ctime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime))
                perms = oct(st.st_mode & 0o777)
                typ = "directory" if is_dir else "file"
                out = (
                    f"Path: {target}\n"
                    f"Type: {typ}\n"
                    f"Size: {size} bytes\n"
                    f"Permissions (octal): {perms}\n"
                    f"Modified: {mtime}\n"
                    f"Accessed: {atime}\n"
                    f"Created: {ctime}"
                )
                return {"ok": True, "stdout": out}
            except Exception as e:
                return {"ok": False, "stderr": f"stat failed: {e}"}

        # read (alias of cat)
        if base == "read":
            if len(parts) < 2:
                return {"ok": False, "stderr": "read requires a filename"}
            target = safe_path(parts[1], base_dir=CURRENT_DIR)
            if not target.exists() or not target.is_file():
                return {"ok": False, "stderr": f"File not found: {target.name}"}
            try:
                text = target.read_text(encoding="utf8")
                return {"ok": True, "stdout": text}
            except Exception as e:
                return {"ok": False, "stderr": f"Could not read file: {e}"}

        # write
        if base == "write":
            if len(parts) < 3:
                return {"ok": False, "stderr": "write requires a filename and text: write filename Hello"}
            fname = parts[1]; content = " ".join(parts[2:])
            target = safe_path(fname, base_dir=CURRENT_DIR)
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf8")
                return {"ok": True, "stdout": f"Wrote {target.name}"}
            except Exception as e:
                return {"ok": False, "stderr": f"Write failed: {e}"}

        # append
        if base == "append":
            if len(parts) < 3:
                return {"ok": False, "stderr": "append requires a filename and text"}
            fname = parts[1]; content = " ".join(parts[2:])
            target = safe_path(fname, base_dir=CURRENT_DIR)
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("a", encoding="utf8") as f:
                    f.write(content)
                return {"ok": True, "stdout": f"Appended to {target.name}"}
            except Exception as e:
                return {"ok": False, "stderr": f"Append failed: {e}"}

        # rm (safe move to trash or permanent)
        if base == "rm":
            recursive = False; permanent = False; confirm = False; targets = []
            for tok in parts[1:]:
                if tok in ("-r", "-R", "--recursive"): recursive = True
                elif tok in ("--permanent", "--perma"): permanent = True
                elif tok == "--yes-i-know": confirm = True
                else: targets.append(tok)
            if not targets:
                return {"ok": False, "stderr": "rm requires at least one target filename or directory"}
            out_lines = []
            for t in targets:
                tgt = safe_path(t, base_dir=CURRENT_DIR)
                if not tgt.exists():
                    out_lines.append(f"{t}: not found"); continue
                if tgt.is_dir() and not recursive and not permanent:
                    out_lines.append(f"{t}: is a directory (use -r or --permanent --yes-i-know)"); continue
                if not permanent:
                    try:
                        msg = _move_to_trash(tgt)
                        out_lines.append(msg)
                    except Exception as e:
                        out_lines.append(f"{t}: failed to move to trash: {e}")
                else:
                    if not confirm:
                        return {"ok": False, "stderr": "Permanent delete requires --yes-i-know flag alongside --permanent"}
                    try:
                        if tgt.is_dir(): shutil.rmtree(tgt)
                        else: tgt.unlink()
                        out_lines.append(f"Deleted permanently: {t}")
                    except Exception as e:
                        out_lines.append(f"{t}: delete failed: {e}")
            return {"ok": True, "stdout": "\n".join(out_lines)}

        # mv
        if base == "mv":
            if len(parts) < 3:
                return {"ok": False, "stderr": "mv requires source and destination: mv src dest"}
            src = safe_path(parts[1], base_dir=CURRENT_DIR)
            dest = safe_path(parts[2], base_dir=CURRENT_DIR)
            if not src.exists():
                return {"ok": False, "stderr": f"Source not found: {parts[1]}"}
            msg = _safe_mv(src, dest)
            return {"ok": True, "stdout": msg}

        # cp (supports -r flag for directories)
        if base == "cp":
            recursive = False
            args = parts[1:]
            if '-r' in args:
                recursive = True
                args = [a for a in args if a != '-r']
            if len(args) < 2:
                return {"ok": False, "stderr": "cp requires source and destination (use -r for directories)"}
            src = safe_path(args[0], base_dir=CURRENT_DIR)
            dest = safe_path(args[1], base_dir=CURRENT_DIR)
            if not src.exists():
                return {"ok": False, "stderr": f"Source not found: {args[0]}"}
            msg = _safe_cp(src, dest, recursive=recursive)
            return {"ok": True, "stdout": msg}

        # restore <name>
        if base == "restore":
            if len(parts) < 2:
                return {"ok": False, "stderr": "restore requires a filename present in .trash/"}
            name = parts[1]
            msg = _restore_from_trash(name, CURRENT_DIR)
            return {"ok": True, "stdout": msg}

        # empty-trash --yes-i-know
        if base == "empty-trash":
            if len(parts) < 2 or parts[1] != "--yes-i-know":
                return {"ok": False, "stderr": "empty-trash is destructive. To confirm run: empty-trash --yes-i-know"}
            trash = ROOT / ".trash"
            if not trash.exists():
                return {"ok": True, "stdout": "Trash is already empty"}
            try:
                for item in trash.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        try: item.unlink()
                        except Exception: pass
                return {"ok": True, "stdout": "Trash emptied"}
            except Exception as e:
                return {"ok": False, "stderr": f"Empty trash failed: {e}"}

        # --- New safe built-in commands ---

        # head
        if base == "head":
            # usage: head [-n NUM] filename
            n = 10
            args = parts[1:]
            if args and args[0] == "-n" and len(args) > 1:
                try:
                    n = int(args[1])
                    args = args[2:]
                except Exception:
                    return {"ok": False, "stderr": "Invalid number for -n"}
            if not args:
                return {"ok": False, "stderr": "head requires a filename"}
            target = safe_path(args[0], base_dir=CURRENT_DIR)
            if not target.exists() or not target.is_file():
                return {"ok": False, "stderr": f"File not found: {args[0]}"}
            try:
                lines = _read_file_lines(target, max_lines=n)
                return {"ok": True, "stdout": "\n".join(lines)}
            except Exception as e:
                return {"ok": False, "stderr": f"head failed: {e}"}

        # tail
        if base == "tail":
            # usage: tail [-n NUM] filename
            n = 10
            args = parts[1:]
            if args and args[0] == "-n" and len(args) > 1:
                try:
                    n = int(args[1])
                    args = args[2:]
                except Exception:
                    return {"ok": False, "stderr": "Invalid number for -n"}
            if not args:
                return {"ok": False, "stderr": "tail requires a filename"}
            target = safe_path(args[0], base_dir=CURRENT_DIR)
            if not target.exists() or not target.is_file():
                return {"ok": False, "stderr": f"File not found: {args[0]}"}
            try:
                lines = _tail_file_lines(target, n=n)
                return {"ok": True, "stdout": "\n".join(lines)}
            except Exception as e:
                return {"ok": False, "stderr": f"tail failed: {e}"}

        # grep
        if base == "grep":
            # usage: grep [-i] [-E] pattern filename
            flags = parts[1:]
            ignore_case = False
            use_regex = False
            pat = None
            fname = None
            # parse flags
            i = 0
            while i < len(flags) and flags[i].startswith("-"):
                if flags[i] == "-i":
                    ignore_case = True
                elif flags[i] == "-E":
                    use_regex = True
                else:
                    pass
                i += 1
            rest = flags[i:]
            if len(rest) < 2:
                return {"ok": False, "stderr": "usage: grep [-i] [-E] pattern filename"}
            pat = rest[0]
            fname = rest[1]
            target = safe_path(fname, base_dir=CURRENT_DIR)
            if not target.exists() or not target.is_file():
                return {"ok": False, "stderr": f"File not found: {fname}"}
            try:
                matches = _grep_in_file(target, pat, ignore_case=ignore_case, use_regex=use_regex)
                if not matches:
                    return {"ok": True, "stdout": ""}
                return {"ok": True, "stdout": "\n".join(matches)}
            except Exception as e:
                return {"ok": False, "stderr": f"grep failed: {e}"}

        # find (search filenames under current dir; simple and safe)
        if base == "find":
            # usage: find [path] [-maxdepth N] [-name pattern]
            args = parts[1:] or ["."]
            start = "."
            maxdepth = 4
            name_pat = None
            i = 0
            if args:
                if not args[0].startswith("-"):
                    start = args[0]
                    i = 1
            while i < len(args):
                a = args[i]
                if a == "-maxdepth" and i+1 < len(args):
                    try:
                        maxdepth = int(args[i+1])
                    except Exception:
                        pass
                    i += 2
                elif a == "-name" and i+1 < len(args):
                    name_pat = args[i+1]
                    i += 2
                else:
                    i += 1
            start_path = safe_path(start, base_dir=CURRENT_DIR)
            out = []
            try:
                for root, dirs, files in os.walk(start_path):
                    rel_root = Path(root)
                    try:
                        depth = len(rel_root.resolve().relative_to(start_path.resolve()).parts) if start_path.resolve() != rel_root.resolve() else 0
                    except Exception:
                        depth = 0
                    if depth > maxdepth:
                        # prune dirs
                        dirs[:] = []
                        continue
                    for f in files:
                        if name_pat:
                            if name_pat in f:
                                out.append(str(Path(root) / f).replace(str(ROOT) + os.sep, ""))
                        else:
                            out.append(str(Path(root) / f).replace(str(ROOT) + os.sep, ""))
                return {"ok": True, "stdout": "\n".join(out)}
            except Exception as e:
                return {"ok": False, "stderr": f"find failed: {e}"}

        # tree
        if base == "tree":
            # usage: tree [path] [-L depth]
            args = parts[1:]
            start = CURRENT_DIR
            max_depth = 3
            if args:
                if not args[0].startswith("-"):
                    start = safe_path(args[0], base_dir=CURRENT_DIR)
                if "-L" in args:
                    try:
                        li = args.index("-L")
                        max_depth = int(args[li+1])
                    except Exception:
                        pass
            try:
                out = _tree_listing(start, max_depth)
                return {"ok": True, "stdout": "\n".join(out)}
            except Exception as e:
                return {"ok": False, "stderr": f"tree failed: {e}"}

        # md5 / sha256
        if base in ("md5", "sha256"):
            if len(parts) < 2:
                return {"ok": False, "stderr": f"{base} requires a filename"}
            target = safe_path(parts[1], base_dir=CURRENT_DIR)
            if not target.exists() or not target.is_file():
                return {"ok": False, "stderr": f"File not found: {parts[1]}"}
            algo = "md5" if base == "md5" else "sha256"
            digest = _compute_hash(target, algo=algo)
            if digest is None:
                return {"ok": False, "stderr": f"{algo} computation failed"}
            return {"ok": True, "stdout": f"{digest}  {target.name}"}

        # wc
        if base == "wc":
            # usage: wc [-l|-w|-c] filename
            args = parts[1:]
            mode = None
            fname = None
            if len(args) == 1:
                fname = args[0]
            elif len(args) == 2:
                mode = args[0]
                fname = args[1]
            else:
                return {"ok": False, "stderr": "usage: wc [-l|-w|-c] filename"}
            target = safe_path(fname, base_dir=CURRENT_DIR)
            if not target.exists() or not target.is_file():
                return {"ok": False, "stderr": f"File not found: {fname}"}
            counts = _wc_counts(target)
            if counts is None:
                return {"ok": False, "stderr": "wc failed to read file"}
            if mode == "-l":
                return {"ok": True, "stdout": str(counts["lines"])}
            if mode == "-w":
                return {"ok": True, "stdout": str(counts["words"])}
            if mode == "-c":
                return {"ok": True, "stdout": str(counts["chars"])}
            # default: lines words chars
            return {"ok": True, "stdout": f"{counts['lines']} {counts['words']} {counts['chars']} {target.name}"}

        # fallback: run as subprocess (Popen) so kill works
        safe_parts = []
        for p in parts:
            if p.startswith("-"):
                safe_parts.append(p)
            elif any(c in p for c in ("/", "\\", ".", "~")) or (not p.isalpha() and len(p) > 0):
                sp = safe_path(p, base_dir=CURRENT_DIR)
                safe_parts.append(str(sp))
            else:
                safe_parts.append(p)

        if os.name == "nt":
            args = windows_translate(safe_parts)
        else:
            args = safe_parts

        res = _spawn_and_wait(args, cwd=CURRENT_DIR)
        if len(res.get("stdout","")) > MAX_OUTPUT_CHARS:
            res["stdout"] = res["stdout"][:MAX_OUTPUT_CHARS] + "\n[truncated output]"
        if len(res.get("stderr","")) > MAX_OUTPUT_CHARS:
            res["stderr"] = res["stderr"][:MAX_OUTPUT_CHARS] + "\n[truncated stderr]"
        return res

    except Exception as e:
        return {"ok": False, "stderr": f"Error: {e}"}


@app.post("/api/kill")
async def api_kill(_req: Request):
    global CURRENT_PROCESS
    with PROCESS_LOCK:
        proc = CURRENT_PROCESS
        if not proc:
            return JSONResponse({"ok": False, "stderr": "No running process to kill."})
        try:
            try:
                proc.terminate()
            except Exception:
                pass
            time.sleep(0.2)
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
            return JSONResponse({"ok": True, "stdout": "Kill signal sent."})
        finally:
            pass


@app.post("/api/command")
async def api_command(req: Request):
    payload = await req.json()
    cmd = payload.get("command", "").strip()
    if not cmd:
        return JSONResponse({"ok": False, "stderr": "No command provided."})
    res = run_whitelisted_command(cmd)
    return JSONResponse(res)


# Serve index.html file (robust to non-utf8 content)
@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = Path.cwd() / "index.html"
    if index_path.exists():
        try:
            # primary: read as UTF-8
            return HTMLResponse(index_path.read_text(encoding="utf8"))
        except UnicodeDecodeError:
            # fallback: read bytes then decode with replacement to avoid 500
            data = index_path.read_bytes()
            text = data.decode("utf-8", errors="replace")
            return HTMLResponse(text)
    return HTMLResponse("<html><body><h3>index.html not found</h3></body></html>")
