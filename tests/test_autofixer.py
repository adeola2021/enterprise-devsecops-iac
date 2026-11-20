import json
from pathlib import Path
import terraform_autofixer as t

SG = '''resource "aws_security_group" "web" {
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
A = Path("a.tf")


def test_sg_only_admin_ports_changed():
    files = {A: SG}
    st, _ = t.fix_sg(files, t.Finding("SG_OPEN_ADMIN", "aws_security_group", "web", "t"), "10.0.0.0/8")
    out = files[A]
    assert st == "applied" and out.count('"10.0.0.0/8"') == 1 and out.count('"0.0.0.0/0"') == 1


def test_sg_range_and_all_protocol_are_fixed():
    src = ('resource "aws_security_group" "w" {\n  ingress {\n    from_port = 0\n    to_port = 65535\n'
           '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n  ingress {\n    from_port = 0\n'
           '    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    files = {A: src}
    st, d = t.fix_sg(files, t.Finding("SG_OPEN_ADMIN", "aws_security_group", "w", "t"), "10.1.0.0/16")
    assert st == "applied" and files[A].count("10.1.0.0/16") == 2


def test_sg_fix_is_idempotent():
    files = {A: SG}
    f = t.Finding("SG_OPEN_ADMIN", "aws_security_group", "web", "t")
    assert t.fix_sg(files, f, "10.0.0.0/8")[0] == "applied"
    assert t.fix_sg(files, f, "10.0.0.0/8")[0] == "skipped"


def test_s3_fix_is_idempotent():
    files = {A: 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'}
    f = t.Finding("S3_ENCRYPTION", "aws_s3_bucket", "b", "t")
    assert t.fix_s3(files, f, None)[0] == "applied"
    assert t.fix_s3(files, f, None)[0] == "skipped"


def test_s3_kms_variant_and_neighbour_preserved():
    files = {A: 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n\nresource "aws_s3_bucket" "c" {\n  bucket = "y"\n}\n'}
    t.fix_s3(files, t.Finding("S3_ENCRYPTION", "aws_s3_bucket", "b", "t"), "arn:aws:kms:x")
    out = files[A]
    assert 'sse_algorithm     = "aws:kms"' in out and 'resource "aws_s3_bucket" "c"' in out
    assert "\n\n\n" not in out


def test_braces_inside_strings_and_heredocs_ignored():
    src = 'resource "aws_s3_bucket" "b" {\n  tags = { n = "}{" }\n  x = <<EOT\n}\nEOT\n}\n'
    (_n, _s, o, c), = list(t.iter_resources(src, "aws_s3_bucket"))
    assert src[c] == "}" and c == len(src.rstrip()) - 1


def test_comment_braces_ignored():
    src = 'resource "aws_s3_bucket" "b" {\n  # } not a close\n  bucket = "x"\n}\n'
    (_n, _s, o, c), = list(t.iter_resources(src, "aws_s3_bucket"))
    assert c == len(src.rstrip()) - 1


def test_iam_is_never_autofixed():
    assert t.fix_iam({}, t.Finding("IAM_WILDCARD", "aws_iam_policy", "p", "t"))[0] == "manual"


def test_load_findings_checkov_and_conftest(tmp_path):
    ck = {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_24", "resource": "aws_security_group.web"},
        {"check_id": "CKV_AWS_999", "resource": "aws_s3_bucket.ignored"}]}}
    ct = [{"failures": [{"msg": "[S3_ENCRYPTION] aws_s3_bucket.logs: no sse"}],
           "warnings": [{"msg": "[IAM_WILDCARD] module.m.aws_iam_policy.p: x"}]}]
    (tmp_path / "c.json").write_text(json.dumps(ck))
    (tmp_path / "o.json").write_text(json.dumps(ct))
    found, skipped = t.load_findings([tmp_path / "c.json", tmp_path / "o.json"])
    assert {(f.rule, f.address) for f in found} == {("SG_OPEN_ADMIN", "aws_security_group.web"),
                                                    ("S3_ENCRYPTION", "aws_s3_bucket.logs")}
    assert skipped and skipped[0]["address"].startswith("module.")


import pytest


def test_check_inputs_rejects_injection_and_open_cidr():
    t.check_inputs("10.0.0.0/8", "arn:aws:kms:us-east-1:111122223333:key/abc-123")
    for cidr, arn in [("0.0.0.0/0", None), ("nonsense", None),
                      ("10.0.0.0/8", 'arn:aws:kms:us-east-1:1:key/x" } oops {')]:
        with pytest.raises(SystemExit):
            t.check_inputs(cidr, arn)
