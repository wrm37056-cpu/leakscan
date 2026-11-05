"""Scan files for accidentally committed secrets (API keys, tokens, private keys)."""
import argparse
import os
import re
import sys

__version__ = "0.1.0"

PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Generic secret": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*['"][^'"\s]{8,}['"]"""
    ),
}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
MAX_BYTES = 1_000_000  # shortcut: skips files over 1 MB, stream line by line if large files matter


def scan_text(text):
    """Yield (line_number, secret_type) for each suspicious line."""
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                yield lineno, name


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                yield os.path.join(root, f)


def scan_paths(paths):
    """Yield (path, line_number, secret_type) for every finding."""
    for path in iter_files(paths):
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable file
        for lineno, name in scan_text(text):
            yield path, lineno, name


def main(argv=None):
    parser = argparse.ArgumentParser(prog="leakscan", description=__doc__)
    parser.add_argument("paths", nargs="*", default=["."], help="files or folders (default: .)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    found = 0
    for path, lineno, name in scan_paths(args.paths):
        # Never print the secret itself: scan output often ends up in CI logs.
        print(f"{path}:{lineno}: {name}")
        found += 1
    print(f"{found} possible secret(s) found.", file=sys.stderr)
    return 1 if found else 0
