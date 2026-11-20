import json
import sys

import terraform_autofixer as tfa

SG = '''resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

FINDINGS = {"results": {"failed_checks": [
    {"check_id": "CKV_AWS_24", "resource": "aws_security_group.web"}]}}


def _run(tmp_path, monkeypatch, validate_result):
    tf = tmp_path / "main.tf"
    tf.write_text(SG)
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps(FINDINGS))
    summary = tmp_path / "summary.json"
    monkeypatch.setattr(tfa, "validate", lambda *a, **k: validate_result)
    monkeypatch.setattr(sys, "argv", [
        "terraform_autofixer.py", "--tf-dir", str(tmp_path),
        "--findings", str(findings), "--summary", str(summary)])
    rc = tfa.main()
    return rc, tf, json.loads(summary.read_text())


def test_rollback_restores_original_when_validate_fails(tmp_path, monkeypatch):
    rc, tf, summary = _run(tmp_path, monkeypatch, (False, "simulated validate failure"))
    assert rc == 1
    assert tf.read_text() == SG            # byte-for-byte original
    assert summary["validated"] is False


def test_patch_kept_when_validate_passes(tmp_path, monkeypatch):
    rc, tf, summary = _run(tmp_path, monkeypatch, (True, "ok"))
    out = tf.read_text()
    assert rc == 0
    assert summary["validated"] is True
    assert out.count("10.0.0.0/8") == 1    # SSH tightened
    assert out.count("0.0.0.0/0") == 1     # 443 rule untouched
