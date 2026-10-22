import json

from agent_sec_scanner.loader import load_text
from agent_sec_scanner.rules import run_rules


def scan(obj, name="cfg.json", **kw):
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return run_rules(load_text(text, name), **kw)


def ids(findings):
    return sorted({f.rule_id for f in findings})


def servers(**entries):
    return {"mcpServers": entries}
