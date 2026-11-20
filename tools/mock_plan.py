#!/usr/bin/env python3
"""mock_plan.py - SANDBOX STAND-IN for `terraform plan && terraform show -json`.

Builds a plan-JSON document (resource_changes + configuration.root_module.resources)
from static HCL, so the Rego policies and Conftest can run where the AWS provider
cannot be downloaded. On a real workstation or in CI, use the genuine plan instead:
    terraform plan -out=tfplan && terraform show -json tfplan > plan.json
Only the fields the Rego policies consume are modelled.
"""
import ast, json, re, sys
from pathlib import Path
import hcl2

REF = re.compile(r"\$\{([a-z0-9_]+\.[A-Za-z0-9_\-]+)(?:\.[A-Za-z0-9_\-\[\]]+)*\}")


def unwrap(v):
    while isinstance(v, list) and len(v) == 1:
        v = v[0]
    return v


def evaluate(v):
    v = unwrap(v)
    if isinstance(v, str):
        m = re.fullmatch(r"\$\{jsonencode\((.*)\)\}", v, re.S)
        if m:
            return json.dumps(ast.literal_eval(m.group(1)))
        return v
    if isinstance(v, list):
        return [evaluate_item(i) for i in v]
    return v


def evaluate_item(i):
    return {k: evaluate(x) for k, x in i.items()} if isinstance(i, dict) else i


def refs(v, out):
    v = unwrap(v)
    if isinstance(v, str):
        for m in REF.finditer(v):
            full = re.search(r"\$\{(.*?)\}", m.group(0)).group(1)
            out.update({full, m.group(1)})
    elif isinstance(v, list):
        [refs(i, out) for i in v]
    elif isinstance(v, dict):
        [refs(i, out) for i in v.values()]


def main(tf_dir, out):
    changes, cfg = [], []
    for p in sorted(Path(tf_dir).rglob("*.tf")):
        data = hcl2.load(p.open())
        for res in data.get("resource", []):
            for rtype, named in res.items():
                for name, body in named.items():
                    body = {k: v for k, v in body.items() if not k.startswith("__")}
                    after = {k: evaluate(v) for k, v in body.items()}
                    if rtype == "aws_security_group":
                        after["ingress"] = [dict(i, ipv6_cidr_blocks=i.get("ipv6_cidr_blocks", [])) for i in after.get("ingress", [])]
                        for i in after["ingress"]:
                            i["cidr_blocks"] = unwrap(i["cidr_blocks"]) if isinstance(unwrap(i["cidr_blocks"]), list) else [unwrap(i["cidr_blocks"])]
                    addr = f"{rtype}.{name}"
                    changes.append({"address": addr, "type": rtype, "name": name,
                                    "change": {"actions": ["create"], "after": after}})
                    exprs = {}
                    for k, v in body.items():
                        r = set(); refs(v, r)
                        if r:
                            exprs[k] = {"references": sorted(r)}
                    cfg.append({"address": addr, "type": rtype, "name": name, "expressions": exprs})
    Path(out).write_text(json.dumps({"format_version": "1.2", "_note": "mock plan (tools/mock_plan.py)",
                                     "resource_changes": changes,
                                     "configuration": {"root_module": {"resources": cfg}}}, indent=2))
    print(f"wrote {out}: {len(changes)} resources")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
