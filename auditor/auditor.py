# auditor/auditor.py
import sys, os, json
from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent

def load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def resolve_imports(playbook_path: Path, visited=None):
    if visited is None:
        visited = set()
    playbook_path = playbook_path.resolve()

    if playbook_path in visited:
        return []
    visited.add(playbook_path)

    data = load_yaml(playbook_path)
    tasks_found = []

    # playbook = list of plays or import directives
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and "import_playbook" in item:
            imported = (playbook_path.parent / item["import_playbook"]).resolve()
            tasks_found.extend(resolve_imports(imported, visited))
        else:
            # normal play
            if isinstance(item, dict) and "tasks" in item and isinstance(item["tasks"], list):
                for t in item["tasks"]:
                    if isinstance(t, dict):
                        tasks_found.append({"file": str(playbook_path), "task": t})
    return tasks_found

def load_policy(policy_path: Path):
    policy = load_yaml(policy_path)
    return policy.get("rules", [])

def detect_violations(tasks, rules):
    violations = []

    for entry in tasks:
        task = entry["task"]
        tname = task.get("name", "(no name)")
        file = entry["file"]

        # rule CIS-SSH-01 + CIS-SSH-02 (lineinfile)
        if "lineinfile" in task:
            li = task["lineinfile"]
            path = li.get("path")
            line = li.get("line", "")

            for rule in rules:
                m = rule.get("match", {})
                if m.get("module") == "lineinfile" and path == m.get("path"):
                    key = m.get("key")
                    expected = rule.get("expected")
                    if key and key in line:
                        # example: "PermitRootLogin yes"
                        parts = line.split()
                        if len(parts) >= 2:
                            value = parts[-1].strip()
                            if value != expected:
                                violations.append({
                                    "rule_id": rule["id"],
                                    "title": rule["title"],
                                    "severity": rule["severity"],
                                    "found_in_task": tname,
                                    "file": file,
                                    "evidence": {"path": path, "line": line, "expected": expected}
                                })

        # rule CIS-FS-01 (mount)
        if "mount" in task:
            mo = task["mount"]
            path = mo.get("path")
            opts = mo.get("opts", "")

            for rule in rules:
                m = rule.get("match", {})
                if m.get("module") == "mount" and path == m.get("path"):
                    banned = set(rule.get("expected_opts_must_not_include", []))
                    # split opts by comma
                    opts_set = set([o.strip() for o in str(opts).split(",") if o.strip()])
                    if banned.intersection(opts_set):
                        violations.append({
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "found_in_task": tname,
                            "file": file,
                            "evidence": {"path": path, "opts": opts, "banned": list(banned)}
                        })

    return violations

def main():
    if len(sys.argv) < 2:
        print("Usage: python auditor.py playbooks/deploy.yml")
        sys.exit(2)

    playbook = (BASE_DIR / sys.argv[1]).resolve()
    policy_path = (BASE_DIR / "policies" / "cis_subset.yml").resolve()
    out_path = (BASE_DIR / "output" / "report.json").resolve()

    tasks = resolve_imports(playbook)
    rules = load_policy(policy_path)
    violations = detect_violations(tasks, rules)

    def rel(p):
        try:
            return str(Path(p).resolve().relative_to(BASE_DIR))
        except ValueError:
            return str(p)

    for v in violations:
        v["file"] = rel(v["file"])

    report = {
        "playbook": rel(playbook),
        "violations_count": len(violations),
        "violations": violations
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    if violations:
        print("NON-CONFORMITÉS DÉTECTÉES :")
        for v in violations:
            print(f"- {v['rule_id']} ({v['severity']}): {v['title']}")
            print(f"  Task: {v['found_in_task']}")
            print(f"  File: {v['file']}")
        print(f"\nReport JSON: {rel(out_path)}")
        sys.exit(1)

    print("Aucun problème détecté.")
    print(f"Report JSON: {rel(out_path)}")
    sys.exit(0)

if __name__ == "__main__":
    main()
