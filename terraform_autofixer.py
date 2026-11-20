#!/usr/bin/env python3
"""terraform_autofixer.py - findings-driven Terraform HCL mutation engine.

Input : Checkov JSON and/or Conftest JSON (from the Rego policies).
Action: surgical text edits -> fmt -> validate (rollback on failure).

Validation modes
  full    : <tf-bin> fmt, init -backend=false, validate   (needs provider registry access)
  offline : <tf-bin> fmt + HCL syntax parse of every .tf   (for air-gapped / sandboxed runs)
"""
from __future__ import annotations
import argparse, difflib, ipaddress, json, re, subprocess, sys
from dataclasses import dataclass
from pathlib import Path

# Checkov check_id -> canonical rule. Verified against Checkov 3.4.5 output.
CHECKOV_RULES = {
    "CKV_AWS_19": "S3_ENCRYPTION", "CKV_AWS_145": "S3_ENCRYPTION",
    "CKV_AWS_24": "SG_OPEN_ADMIN", "CKV_AWS_25": "SG_OPEN_ADMIN",
    "CKV_AWS_49": "IAM_WILDCARD", "CKV_AWS_63": "IAM_WILDCARD", "CKV_AWS_355": "IAM_WILDCARD",
}
CONFTEST_MSG = re.compile(r"^\[(?P<rule>[A-Z0-9_]+)\]\s+(?P<addr>\S+):")
HEREDOC = re.compile(r"<<-?(\w+)\n")


@dataclass(frozen=True)
class Finding:
    rule: str
    rtype: str
    rname: str
    source: str

    @property
    def address(self) -> str:
        return f"{self.rtype}.{self.rname}"


# ───────────────────── Input hardening (values are written into HCL) ─────────────────────
KMS_RE = re.compile(r"^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)/[A-Za-z0-9/_+=,.@-]+$")


def check_inputs(cidr: str, kms_arn: str | None):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise SystemExit(f"invalid --admin-cidr: {e}")
    if net.prefixlen == 0:
        raise SystemExit("--admin-cidr must not be a /0 (that would re-open the port)")
    if kms_arn and not KMS_RE.match(kms_arn):
        raise SystemExit(f"invalid --kms-key-arn: {kms_arn!r}")


# ───────────────────────── HCL scanning helpers ─────────────────────────
def skip_string(text: str, i: int) -> int:
    """i is at an opening quote; return index after the closing quote."""
    i += 1
    interp = 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if text.startswith(("${", "%{"), i):
            interp += 1
            i += 2
            continue
        if interp:
            if c == '"':
                i = skip_string(text, i)
                continue
            if c == "{":
                interp += 1
            elif c == "}":
                interp -= 1
        elif c == '"':
            return i + 1
        i += 1
    raise ValueError("unterminated string")


def match_brace(text: str, start: int) -> int:
    """start is at '{'; return the index of the matching '}' (skips strings, comments, heredocs)."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c == "#" or text.startswith("//", i):
            nl = text.find("\n", i)
            if nl == -1:
                break
            i = nl
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i)
            i = n if end == -1 else end + 2
            continue
        hd = HEREDOC.match(text, i)
        if hd:
            term = re.compile(rf"^[ \t]*{re.escape(hd.group(1))}[ \t]*$", re.M).search(text, hd.end())
            i = term.end() if term else n
            continue
        if c == '"':
            i = skip_string(text, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced braces")


def iter_resources(text: str, rtype: str):
    pat = re.compile(rf'^[ \t]*resource\s+"{re.escape(rtype)}"\s+"([^"]+)"\s*\{{', re.M)
    for m in pat.finditer(text):
        o = m.end() - 1
        yield m.group(1), m.start(), o, match_brace(text, o)


def locate(files: dict[Path, str], rtype: str, rname: str):
    for path, text in files.items():
        for name, _s, o, c in iter_resources(text, rtype):
            if name == rname:
                return path, o, c
    return None


# ───────────────────────────── Fixers ─────────────────────────────
def fix_s3(files, f: Finding, kms_arn: str | None):
    loc = locate(files, f.rtype, f.rname)
    if not loc:
        return "skipped", "resource not found in scanned files"
    # Idempotency: is there already an SSE resource pointing at this bucket?
    for text in files.values():
        for _n, _s, o, c in iter_resources(text, "aws_s3_bucket_server_side_encryption_configuration"):
            if re.search(rf"aws_s3_bucket\.{re.escape(f.rname)}\b", text[o:c]):
                return "skipped", "encryption resource already exists"
    path, _o, close = loc
    algo = (f'sse_algorithm     = "aws:kms"\n      kms_master_key_id = "{kms_arn}"'
            if kms_arn else 'sse_algorithm = "AES256"')
    block = (
        f'resource "aws_s3_bucket_server_side_encryption_configuration" "{f.rname}_sse" {{\n'
        f"  bucket = aws_s3_bucket.{f.rname}.id\n\n"
        f"  rule {{\n    apply_server_side_encryption_by_default {{\n      {algo}\n    }}\n  }}\n}}\n"
    )
    t = files[path]
    rest = t[close + 1:].lstrip("\n")
    files[path] = t[: close + 1] + "\n\n" + block + ("\n" + rest if rest.strip() else "")
    return "applied", "added aws_s3_bucket_server_side_encryption_configuration (" + ("KMS" if kms_arn else "AES256") + ")"


def tighten(block: str, cidr: str):
    """Replace 0.0.0.0/0 in one ingress block, only if it exposes 22/3389 (or all protocols)."""
    fp = re.search(r"from_port\s*=\s*(\d+)", block)
    tp = re.search(r"to_port\s*=\s*(\d+)", block)
    pr = re.search(r'protocol\s*=\s*"([^"]+)"', block)
    if not (fp and tp):
        return block, 0
    lo, hi = int(fp[1]), int(tp[1])
    if not ((pr and pr[1] == "-1") or any(lo <= p <= hi for p in (22, 3389))):
        return block, 0
    return re.subn(r'"0\.0\.0\.0/0"', f'"{cidr}"', block)


def fix_sg(files, f: Finding, cidr: str):
    loc = locate(files, f.rtype, f.rname)
    if not loc:
        return "skipped", "resource not found in scanned files"
    path, o, c = loc
    text = files[path]
    body, total = text[o + 1:c], 0
    if f.rtype == "aws_security_group_rule":
        if re.search(r'type\s*=\s*"ingress"', body):
            body, total = tighten(body, cidr)
    else:
        for m in reversed(list(re.finditer(r"\bingress\s*\{", body))):  # reverse keeps indices valid
            ob = m.end() - 1
            cb = match_brace(body, ob)
            new, n = tighten(body[ob:cb + 1], cidr)
            body, total = body[:ob] + new + body[cb + 1:], total + n
    if not total:
        return "skipped", "nothing left to change (already remediated, or CIDR is dynamic/variable)"
    files[path] = text[: o + 1] + body + text[c:]
    return "applied", f"restricted {total} admin ingress rule(s) to {cidr}"


def fix_iam(files, f: Finding, *_):
    return "manual", "wildcard IAM needs a human-authored least-privilege policy"


# ───────────────────────── Findings ingestion ─────────────────────────
def load_findings(paths):
    found, skipped = set(), []

    def add(rule, addr, src):
        addr = re.sub(r"\[.*?\]$", "", addr)
        if addr.startswith("module.") or "." not in addr:
            skipped.append({"address": addr, "reason": "module/unsupported address"})
            return
        rtype, rname = addr.split(".", 1)
        found.add(Finding(rule, rtype, rname, src))

    for p in paths:
        data = json.loads(Path(p).read_text())
        reports = data if isinstance(data, list) and data and isinstance(data[0], dict) and "check_type" in data[0] \
            else [data] if isinstance(data, dict) and "results" in data else []
        for rep in reports:                                   # Checkov
            for fc in (rep.get("results") or {}).get("failed_checks", []):
                if fc["check_id"] in CHECKOV_RULES:
                    add(CHECKOV_RULES[fc["check_id"]], fc["resource"], f"checkov:{fc['check_id']}")
        if isinstance(data, list):                            # Conftest / OPA
            for item in data:
                for r in (item.get("failures") or []) + (item.get("warnings") or []):
                    m = CONFTEST_MSG.match(r.get("msg", ""))
                    if m:
                        add(m["rule"], m["addr"], "opa")
    return sorted(found, key=lambda x: (x.rule, x.address, x.source)), skipped


# ───────────────────────────── Validation ─────────────────────────────
def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def hcl_syntax_check(tf_dir: str):
    try:
        import hcl2
    except ImportError:
        return False, "hcl2 module not installed; cannot syntax-check"
    out = []
    for p in sorted(Path(tf_dir).rglob("*.tf")):
        try:
            with p.open() as fh:
                hcl2.load(fh)
            out.append(f"hcl2 parse OK: {p}")
        except Exception as e:  # noqa: BLE001
            return False, "\n".join(out + [f"hcl2 parse FAILED: {p}: {e}"])
    return True, "\n".join(out)


def validate(tf_dir: str, tf_bin: str, mode: str):
    log = []
    ok, out = run([tf_bin, "fmt", "-recursive"], tf_dir)
    log.append(f"$ {tf_bin} fmt -recursive\n{out}")
    if not ok:
        return False, "\n".join(log)
    if mode == "offline":
        ok, out = hcl_syntax_check(tf_dir)
        log.append(f"$ <hcl2 syntax check>  (offline mode: init/validate skipped)\n{out}")
        return ok, "\n".join(log)
    for cmd in ([tf_bin, "init", "-backend=false", "-input=false"], [tf_bin, "validate"]):
        ok, out = run(cmd, tf_dir)
        log.append(f"$ {' '.join(cmd)}\n{out}")
        if not ok:
            return False, "\n".join(log)
    return True, "\n".join(log)


# ──────────────────────────────── Main ────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tf-dir", required=True)
    ap.add_argument("--findings", action="append", required=True)
    ap.add_argument("--admin-cidr", default="10.0.0.0/8", help="replacement CIDR for open SSH/RDP")
    ap.add_argument("--kms-key-arn", help="use SSE-KMS (needed to satisfy Checkov CKV_AWS_145)")
    ap.add_argument("--tf-bin", default="terraform", help="terraform or tofu binary")
    ap.add_argument("--validate-mode", choices=["full", "offline"], default="full")
    ap.add_argument("--summary", default="reports/autofix_summary.json")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    check_inputs(a.admin_cidr, a.kms_key_arn)
    findings, skipped = load_findings(a.findings)
    paths = sorted(Path(a.tf_dir).rglob("*.tf"))
    original = {p: p.read_text() for p in paths}
    files = dict(original)
    results = []

    for f in findings:
        try:
            if f.rule == "S3_ENCRYPTION":
                st, detail = fix_s3(files, f, a.kms_key_arn)
            elif f.rule == "SG_OPEN_ADMIN":
                st, detail = fix_sg(files, f, a.admin_cidr)
            elif f.rule == "IAM_WILDCARD":
                st, detail = fix_iam(files, f)
            else:
                continue
        except ValueError as e:      # unparsable HCL: report, never crash the run
            st, detail = "error", f"HCL scan failed: {e}"
        results.append({"rule": f.rule, "resource": f.address, "source": f.source, "status": st, "detail": detail})
        print(f"[{st.upper():7}] {f.rule:14} {f.address:36} {f.source:18} {detail}")

    changed = [p for p in paths if files[p] != original[p]]
    validated = None
    if a.dry_run:
        for p in changed:
            sys.stdout.writelines(difflib.unified_diff(
                original[p].splitlines(True), files[p].splitlines(True), f"a/{p}", f"b/{p}"))
    elif changed:
        for p in changed:
            p.write_text(files[p])
        validated, log = validate(a.tf_dir, a.tf_bin, a.validate_mode)
        print(log)
        if not validated:
            for p in changed:
                p.write_text(original[p])   # rollback
            print("!! validation failed - changes rolled back", file=sys.stderr)

    Path(a.summary).parent.mkdir(parents=True, exist_ok=True)
    Path(a.summary).write_text(json.dumps(
        {"results": results, "unsupported": skipped, "files_changed": [str(p) for p in changed],
         "validated": validated, "validate_mode": a.validate_mode, "dry_run": a.dry_run}, indent=2))
    return 1 if validated is False else 0


if __name__ == "__main__":
    sys.exit(main())
