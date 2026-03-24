from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ATTACK_DATASETS: Dict[str, str] = {
    "enterprise-attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile-attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics-attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
DIFFS_DIR = DATA_DIR / "diffs"
REPORTS_DIR = DATA_DIR / "reports"
CSV_DIR = DATA_DIR / "csv"

HTTP_TIMEOUT = 90

IGNORED_FIELDS_FOR_SEMANTIC_DIFF = {
    "modified",
    "x_mitre_modified_by_ref",
    "created_by_ref",
    "object_marking_refs",
    "spec_version",
}

KEY_FIELDS = {
    "name",
    "description",
    "aliases",
    "x_mitre_version",
    "x_mitre_platforms",
    "x_mitre_domains",
    "x_mitre_data_sources",
    "x_mitre_detection",
    "x_mitre_is_subtechnique",
    "x_mitre_deprecated",
    "revoked",
    "first_seen",
    "last_seen",
}

HIGH_SIGNAL_RELATIONSHIPS = {"uses", "targets", "attributed-to"}

TRACKED_TYPES = {
    "attack-pattern",
    "intrusion-set",
    "campaign",
    "malware",
    "tool",
    "relationship",
    "course-of-action",
    "x-mitre-data-source",
    "x-mitre-data-component",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def today_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def ensure_dirs() -> None:
    for d in (DATA_DIR, SNAPSHOTS_DIR, DIFFS_DIR, REPORTS_DIR, CSV_DIR):
        d.mkdir(parents=True, exist_ok=True)


def stable_json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fetch_json(url: str) -> Dict[str, Any]:
    req = Request(
        url,
        headers={
            "User-Agent": "attack-cti-watch/2.0",
            "Accept": "application/json",
        },
        method="GET",
    )

    with urlopen(req, timeout=HTTP_TIMEOUT) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw)


def save_json(path: Path, data: Any) -> None:
    path.write_text(stable_json_dumps(data), encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def list_snapshots_for_domain(domain: str) -> List[Path]:
    return sorted(SNAPSHOTS_DIR.glob(f"*__{domain}.json"))


def get_previous_snapshot_path(domain: str, current_date: str) -> Optional[Path]:
    previous = None

    for path in list_snapshots_for_domain(domain):
        date_part = path.name.split("__", 1)[0]
        if date_part < current_date:
            previous = path

    return previous


def normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: normalize_value(value[k]) for k in sorted(value.keys())}

    if isinstance(value, list):
        normalized = [normalize_value(v) for v in value]

        if all(isinstance(v, (str, int, float, bool, type(None))) for v in normalized):
            return sorted(normalized, key=lambda x: str(x))

        return sorted(normalized, key=lambda x: stable_json_dumps(x))

    return value


def object_for_semantic_diff(obj: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = {}

    for key, value in obj.items():
        if key in IGNORED_FIELDS_FOR_SEMANTIC_DIFF:
            continue
        cleaned[key] = normalize_value(value)

    return cleaned


def filter_stix_objects(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = []

    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "marking-definition":
            continue
        if "type" not in obj or "id" not in obj:
            continue
        if obj.get("type") not in TRACKED_TYPES:
            continue
        result.append(obj)

    return result


def get_attack_external_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def get_display_name(obj: Dict[str, Any]) -> str:
    if obj.get("type") == "relationship":
        return obj.get("relationship_type") or obj.get("id") or "unknown"
    return obj.get("name") or obj.get("id") or "unknown"


def object_identity_key(obj: Dict[str, Any]) -> str:
    return obj["id"]


def relationship_key(obj: Dict[str, Any]) -> str:
    src = obj.get("source_ref", "")
    rel = obj.get("relationship_type", "")
    tgt = obj.get("target_ref", "")
    return f"{src}|{rel}|{tgt}"


def index_objects(objects: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {object_identity_key(obj): obj for obj in objects}


def index_relationships(objects: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    rels = {}

    for obj in objects:
        if obj.get("type") == "relationship":
            rels[relationship_key(obj)] = obj

    return rels


def resolve_ref_name(ref: str, index_by_id: Dict[str, Dict[str, Any]]) -> str:
    obj = index_by_id.get(ref)
    if not obj:
        return ref

    attack_id = get_attack_external_id(obj) or "-"
    name = get_display_name(obj)
    obj_type = obj.get("type") or "-"
    return f"{attack_id} | {obj_type} | {name}"


def changed_fields_between(old_obj: Dict[str, Any], new_obj: Dict[str, Any]) -> List[str]:
    old_clean = object_for_semantic_diff(old_obj)
    new_clean = object_for_semantic_diff(new_obj)

    keys = sorted(set(old_clean.keys()) | set(new_clean.keys()))
    changed = []

    for key in keys:
        if old_clean.get(key) != new_clean.get(key):
            changed.append(key)

    return changed


def extract_field_samples(old_obj: Dict[str, Any], new_obj: Dict[str, Any], fields: List[str]) -> Dict[str, Dict[str, Any]]:
    result = {}

    for field in fields:
        if field not in KEY_FIELDS:
            continue
        result[field] = {
            "old": old_obj.get(field),
            "new": new_obj.get(field),
        }

    return result


def classify_cti_priority(obj: Dict[str, Any], changed_fields: Optional[List[str]] = None) -> str:
    changed_fields = changed_fields or []
    obj_type = obj.get("type")

    if obj_type == "campaign":
        return "high"

    if obj_type == "relationship":
        if obj.get("relationship_type") in HIGH_SIGNAL_RELATIONSHIPS:
            return "high"
        return "medium"

    if obj_type == "attack-pattern":
        return "high"

    if obj_type in {"intrusion-set", "malware", "tool"}:
        return "high"

    if any(field in changed_fields for field in {"description", "aliases", "x_mitre_detection", "x_mitre_data_sources", "x_mitre_platforms"}):
        return "medium"

    return "low"


def summarize_object(obj: Dict[str, Any], full_index: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    item = {
        "stix_id": obj.get("id"),
        "type": obj.get("type"),
        "attack_id": get_attack_external_id(obj),
        "name": obj.get("name"),
        "modified": obj.get("modified"),
        "revoked": obj.get("revoked", False),
        "deprecated": obj.get("x_mitre_deprecated", False),
    }

    if obj.get("type") == "relationship":
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        item["relationship_type"] = obj.get("relationship_type")
        item["source_ref"] = source_ref
        item["target_ref"] = target_ref

        if full_index is not None:
            item["source_name"] = resolve_ref_name(source_ref, full_index)
            item["target_name"] = resolve_ref_name(target_ref, full_index)

    return item


def is_cti_relevant_update(obj: Dict[str, Any], changed_fields: List[str]) -> bool:
    obj_type = obj.get("type")

    if obj_type in {"attack-pattern", "intrusion-set", "campaign", "malware", "tool"}:
        return True

    if obj_type == "relationship":
        return True

    if any(field in changed_fields for field in KEY_FIELDS):
        return True

    return False


def compare_bundles(old_bundle: Dict[str, Any], new_bundle: Dict[str, Any], domain: str, previous_snapshot: Optional[str]) -> Dict[str, Any]:
    old_objects = filter_stix_objects(old_bundle)
    new_objects = filter_stix_objects(new_bundle)

    old_index = index_objects(old_objects)
    new_index = index_objects(new_objects)
    old_rel_index = index_relationships(old_objects)
    new_rel_index = index_relationships(new_objects)

    new_objects_found = []
    updated_objects_found = []
    revoked_objects_found = []
    deprecated_objects_found = []
    new_relationships_found = []

    for stix_id, new_obj in new_index.items():
        old_obj = old_index.get(stix_id)

        if old_obj is None:
            entry = summarize_object(new_obj, new_index)
            entry["priority"] = classify_cti_priority(new_obj)
            new_objects_found.append(entry)
            continue

        changed_fields = changed_fields_between(old_obj, new_obj)

        if changed_fields and is_cti_relevant_update(new_obj, changed_fields):
            entry = summarize_object(new_obj, new_index)
            entry["priority"] = classify_cti_priority(new_obj, changed_fields)
            entry["changed_fields"] = changed_fields
            entry["field_samples"] = extract_field_samples(old_obj, new_obj, changed_fields)
            updated_objects_found.append(entry)

        if not old_obj.get("revoked", False) and new_obj.get("revoked", False):
            entry = summarize_object(new_obj, new_index)
            entry["priority"] = "high"
            revoked_objects_found.append(entry)

        if not old_obj.get("x_mitre_deprecated", False) and new_obj.get("x_mitre_deprecated", False):
            entry = summarize_object(new_obj, new_index)
            entry["priority"] = "medium"
            deprecated_objects_found.append(entry)

    for rel_key, rel_obj in new_rel_index.items():
        if rel_key not in old_rel_index:
            entry = summarize_object(rel_obj, new_index)
            entry["priority"] = classify_cti_priority(rel_obj)
            new_relationships_found.append(entry)

    new_objects_found.sort(key=lambda x: (x.get("type") or "", x.get("attack_id") or "", x.get("name") or ""))
    updated_objects_found.sort(key=lambda x: (x.get("type") or "", x.get("attack_id") or "", x.get("name") or ""))
    revoked_objects_found.sort(key=lambda x: (x.get("type") or "", x.get("attack_id") or "", x.get("name") or ""))
    deprecated_objects_found.sort(key=lambda x: (x.get("type") or "", x.get("attack_id") or "", x.get("name") or ""))
    new_relationships_found.sort(key=lambda x: (x.get("relationship_type") or "", x.get("source_ref") or "", x.get("target_ref") or ""))

    return {
        "metadata": {
            "domain": domain,
            "generated_at": utc_now_iso(),
            "previous_snapshot_date": previous_snapshot,
        },
        "counts": {
            "new_objects": len(new_objects_found),
            "updated_objects": len(updated_objects_found),
            "revoked_objects": len(revoked_objects_found),
            "deprecated_objects": len(deprecated_objects_found),
            "new_relationships": len(new_relationships_found),
        },
        "new_objects": new_objects_found,
        "updated_objects": updated_objects_found,
        "revoked_objects": revoked_objects_found,
        "deprecated_objects": deprecated_objects_found,
        "new_relationships": new_relationships_found,
    }


def build_snapshot_bundle(raw_bundle: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    return {
        "metadata": {
            "fetched_at": utc_now_iso(),
            "source_url": source_url,
        },
        "bundle": raw_bundle,
    }


def save_snapshot(domain: str, date_str: str, source_url: str, raw_bundle: Dict[str, Any]) -> Path:
    snapshot_bundle = build_snapshot_bundle(raw_bundle, source_url)
    text = stable_json_dumps(snapshot_bundle)
    path = SNAPSHOTS_DIR / f"{date_str}__{domain}.json"
    path.write_text(text, encoding="utf-8")
    return path


def extract_bundle_from_snapshot(snapshot_data: Dict[str, Any]) -> Dict[str, Any]:
    return snapshot_data["bundle"]


def count_by_type(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {}

    for item in items:
        obj_type = item.get("type") or "unknown"
        counts[obj_type] = counts.get(obj_type, 0) + 1

    return dict(sorted(counts.items(), key=lambda kv: kv[0]))


def top_items(items: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    priority_rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        items,
        key=lambda x: (
            priority_rank.get(x.get("priority", "low"), 9),
            x.get("type") or "",
            x.get("attack_id") or "",
            x.get("name") or "",
        ),
    )[:limit]


def format_object_line(item: Dict[str, Any]) -> str:
    priority = item.get("priority") or "-"
    attack_id = item.get("attack_id") or "-"
    obj_type = item.get("type") or "-"
    name = item.get("name") or item.get("relationship_type") or "-"
    return f"- [{priority}] {attack_id} | {obj_type} | {name}"


def format_relationship_line(item: Dict[str, Any]) -> str:
    priority = item.get("priority") or "-"
    rel_type = item.get("relationship_type") or "-"
    src = item.get("source_name") or item.get("source_ref") or "-"
    tgt = item.get("target_name") or item.get("target_ref") or "-"
    return f"- [{priority}] {rel_type} | {src} -> {tgt}"


def generate_cti_notes(diff: Dict[str, Any]) -> List[str]:
    notes = []

    for item in diff["new_objects"]:
        obj_type = item.get("type")
        if obj_type == "campaign":
            notes.append(f"Nova campaign adicionada: {item.get('name') or item.get('stix_id')}")
        elif obj_type == "intrusion-set":
            notes.append(f"Novo grupo adicionando tracking novo: {item.get('name') or item.get('stix_id')}")
        elif obj_type == "malware":
            notes.append(f"Novo malware na base ATT&CK: {item.get('name') or item.get('stix_id')}")
        elif obj_type == "tool":
            notes.append(f"Nova tool adicionada: {item.get('name') or item.get('stix_id')}")
        elif obj_type == "attack-pattern":
            if item.get("attack_id"):
                notes.append(f"Nova técnica/sub-technique: {item.get('attack_id')} {item.get('name') or ''}".strip())

    for item in diff["updated_objects"]:
        fields = set(item.get("changed_fields", []))
        if "aliases" in fields:
            notes.append(f"Aliases mudaram em {item.get('attack_id') or item.get('stix_id')}: revisar tracking e pivot por nomes alternativos")
        if "x_mitre_platforms" in fields:
            notes.append(f"Platforms mudaram em {item.get('attack_id') or item.get('stix_id')}: revisar escopo operacional")
        if "x_mitre_data_sources" in fields:
            notes.append(f"Data sources mudaram em {item.get('attack_id') or item.get('stix_id')}: revisar coleta e cobertura")
        if "x_mitre_detection" in fields:
            notes.append(f"Detection mudou em {item.get('attack_id') or item.get('stix_id')}: revisar analytics e hunting")
        if "description" in fields:
            notes.append(f"Descrição mudou em {item.get('attack_id') or item.get('stix_id')}: revisar contexto e procedure understanding")

    for item in diff["new_relationships"]:
        rel_type = item.get("relationship_type")
        if rel_type == "uses":
            notes.append("Nova relação uses detectada: revisar associação entre ator/software/campaign e técnica")
        elif rel_type == "attributed-to":
            notes.append("Nova relação attributed-to detectada: revisar atribuição e tracking de campanha/grupo")
        elif rel_type == "targets":
            notes.append("Nova relação targets detectada: revisar alvo/setor/tecnologia relacionada")

    deduped = []
    seen = set()

    for note in notes:
        if note not in seen:
            seen.add(note)
            deduped.append(note)

    return deduped[:20]


def generate_markdown_report(diff: Dict[str, Any]) -> str:
    metadata = diff["metadata"]
    counts = diff["counts"]

    new_objects = diff["new_objects"]
    updated_objects = diff["updated_objects"]
    revoked_objects = diff["revoked_objects"]
    deprecated_objects = diff["deprecated_objects"]
    new_relationships = diff["new_relationships"]

    lines = []

    lines.append(f"# ATT&CK Daily CTI Watch - {metadata['domain']}")
    lines.append("")
    lines.append(f"- Generated at: {metadata['generated_at']}")
    lines.append(f"- Previous snapshot date: {metadata.get('previous_snapshot_date') or 'N/A'}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- New objects: {counts['new_objects']}")
    lines.append(f"- Updated objects: {counts['updated_objects']}")
    lines.append(f"- Revoked objects: {counts['revoked_objects']}")
    lines.append(f"- Deprecated objects: {counts['deprecated_objects']}")
    lines.append(f"- New relationships: {counts['new_relationships']}")
    lines.append("")

    lines.append("## New objects by type")
    lines.append("")
    new_type_counts = count_by_type(new_objects)
    if new_type_counts:
        for obj_type, count in new_type_counts.items():
            lines.append(f"- {obj_type}: {count}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Updated objects by type")
    lines.append("")
    updated_type_counts = count_by_type(updated_objects)
    if updated_type_counts:
        for obj_type, count in updated_type_counts.items():
            lines.append(f"- {obj_type}: {count}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## CTI notes")
    lines.append("")
    notes = generate_cti_notes(diff)
    if notes:
        for note in notes:
            lines.append(f"- {note}")
    else:
        lines.append("- Nenhum ponto de atenção adicional")
    lines.append("")

    lines.append("## Highlights - New objects")
    lines.append("")
    if new_objects:
        for item in top_items(new_objects):
            lines.append(format_object_line(item))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Highlights - Updated objects")
    lines.append("")
    if updated_objects:
        for item in top_items(updated_objects):
            changed_fields = ", ".join(item.get("changed_fields", [])) or "-"
            priority = item.get("priority") or "-"
            attack_id = item.get("attack_id") or "-"
            obj_type = item.get("type") or "-"
            name = item.get("name") or "-"
            lines.append(f"- [{priority}] {attack_id} | {obj_type} | {name} | changed: {changed_fields}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Highlights - New relationships")
    lines.append("")
    if new_relationships:
        for item in top_items(new_relationships):
            lines.append(format_relationship_line(item))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Revoked")
    lines.append("")
    if revoked_objects:
        for item in revoked_objects:
            lines.append(format_object_line(item))
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Deprecated")
    lines.append("")
    if deprecated_objects:
        for item in deprecated_objects:
            lines.append(format_object_line(item))
    else:
        lines.append("- None")
    lines.append("")

    return "\n".join(lines).strip() + "\n"


def write_summary_csv(path: Path, diff: Dict[str, Any]) -> None:
    rows = []

    for section_name in ("new_objects", "updated_objects", "revoked_objects", "deprecated_objects", "new_relationships"):
        for item in diff[section_name]:
            rows.append({
                "section": section_name,
                "priority": item.get("priority"),
                "type": item.get("type"),
                "attack_id": item.get("attack_id"),
                "name": item.get("name"),
                "relationship_type": item.get("relationship_type"),
                "source_name": item.get("source_name"),
                "target_name": item.get("target_name"),
                "changed_fields": ",".join(item.get("changed_fields", [])),
                "stix_id": item.get("stix_id"),
                "modified": item.get("modified"),
            })

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "section",
                "priority",
                "type",
                "attack_id",
                "name",
                "relationship_type",
                "source_name",
                "target_name",
                "changed_fields",
                "stix_id",
                "modified",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(domain: str, date_str: str, diff: Dict[str, Any]) -> None:
    diff_path = DIFFS_DIR / f"{date_str}__{domain}__diff.json"
    report_path = REPORTS_DIR / f"{date_str}__{domain}__report.md"
    csv_path = CSV_DIR / f"{date_str}__{domain}__summary.csv"

    save_json(diff_path, diff)
    report_path.write_text(generate_markdown_report(diff), encoding="utf-8")
    write_summary_csv(csv_path, diff)


def build_empty_diff(domain: str) -> Dict[str, Any]:
    return {
        "metadata": {
            "domain": domain,
            "generated_at": utc_now_iso(),
            "previous_snapshot_date": None,
            "note": "primeiro snapshot salvo; ainda não existe baseline anterior",
        },
        "counts": {
            "new_objects": 0,
            "updated_objects": 0,
            "revoked_objects": 0,
            "deprecated_objects": 0,
            "new_relationships": 0,
        },
        "new_objects": [],
        "updated_objects": [],
        "revoked_objects": [],
        "deprecated_objects": [],
        "new_relationships": [],
    }


def process_domain(domain: str) -> int:
    if domain not in ATTACK_DATASETS:
        print(f"[ERRO] domínio inválido: {domain}", file=sys.stderr)
        return 1

    date_str = today_utc_str()
    source_url = ATTACK_DATASETS[domain]

    try:
        raw_bundle = fetch_json(source_url)
    except HTTPError as exc:
        print(f"[ERRO] HTTP ao baixar {domain}: {exc}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"[ERRO] rede ao baixar {domain}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERRO] falha ao baixar {domain}: {exc}", file=sys.stderr)
        return 1

    snapshot_path = save_snapshot(domain, date_str, source_url, raw_bundle)

    previous_path = get_previous_snapshot_path(domain, date_str)

    if previous_path is None:
        diff = build_empty_diff(domain)
        write_outputs(domain, date_str, diff)

        print(f"[OK] {domain}")
        print(f"  snapshot: {snapshot_path}")
        print("  baseline anterior: não existe")
        print("  diff/report/csv: gerados")
        return 0

    old_snapshot = load_json(previous_path)
    old_bundle = extract_bundle_from_snapshot(old_snapshot)
    previous_date = previous_path.name.split("__", 1)[0]

    diff = compare_bundles(
        old_bundle=old_bundle,
        new_bundle=raw_bundle,
        domain=domain,
        previous_snapshot=previous_date,
    )

    write_outputs(domain, date_str, diff)

    print(f"[OK] {domain}")
    print(f"  snapshot: {snapshot_path}")
    print(f"  previous: {previous_path}")
    print(f"  new_objects: {diff['counts']['new_objects']}")
    print(f"  updated_objects: {diff['counts']['updated_objects']}")
    print(f"  revoked_objects: {diff['counts']['revoked_objects']}")
    print(f"  deprecated_objects: {diff['counts']['deprecated_objects']}")
    print(f"  new_relationships: {diff['counts']['new_relationships']}")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Watcher diário do MITRE ATT&CK para CTI")

    parser.add_argument(
        "--domain",
        nargs="+",
        default=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="Domínios ATT&CK para monitorar",
    )

    return parser.parse_args()


def main() -> int:
    ensure_dirs()
    args = parse_args()

    rc_final = 0

    for domain in args.domain:
        rc = process_domain(domain)
        if rc != 0:
            rc_final = rc

    return rc_final


if __name__ == "__main__":
    raise SystemExit(main())
