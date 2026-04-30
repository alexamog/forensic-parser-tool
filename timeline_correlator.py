import os
import json
from forensic_helpers import is_valid_timestamp


RESULTS_DIR = "results"

LNK_RESULTS = os.path.join(RESULTS_DIR, "lnk_results.json")
PREFETCH_RESULTS = os.path.join(RESULTS_DIR, "prefetch_results.json")
RECYCLE_BIN_RESULTS = os.path.join(RESULTS_DIR, "recycle_bin_results.json")
SHIMCACHE_RESULTS = os.path.join(RESULTS_DIR, "shimcache_results.json")


def load_json(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


def extract_lnk_events(results: list[dict]) -> list[dict]:
    events = []
    for entry in results:
        if "error" in entry:
            continue
        source = entry.get("file", "unknown")
        target = entry.get("target_path", "unknown")

        # Use last_access_time only - most forensically relevant for LNK files
        # Filter out 1980-01-01 placeholder timestamps - these indicate an unset field
        ts = entry.get("last_access_time")
        if is_valid_timestamp(ts):
            events.append({
                "timestamp": ts,
                "artifact": "LNK",
                "description": f"File accessed: {target}",
                "source_file": source,
            })
    return events


def extract_prefetch_events(results: list[dict]) -> list[dict]:
    events = []
    for entry in results:
        if "error" in entry:
            continue
        source = entry.get("file", "unknown")
        exe = entry.get("executable", "unknown")
        run_count = entry.get("execution_count", "?")

        for ts in entry.get("last_run_times", []):
            if is_valid_timestamp(ts):
                events.append({
                    "timestamp": ts,
                    "artifact": "Prefetch",
                    "description": f"Program executed: {exe} (run count: {run_count})",
                    "source_file": source,
                })
    return events


def extract_recycle_bin_events(results: list[dict]) -> list[dict]:
    events = []
    for entry in results:
        if "error" in entry:
            continue
        source = entry.get("file", "unknown")
        path = entry.get("original_path", "unknown").rstrip("\x00")
        sid = entry.get("sid", "unknown")
        rid = sid.split("-")[-1] if "-" in sid else sid

        ts = entry.get("deletion_timestamp")
        if is_valid_timestamp(ts):
            events.append({
                "timestamp": ts,
                "artifact": "Recycle Bin",
                "description": f"File deleted: {path} (user RID: {rid})",
                "source_file": source,
            })
    return events


def extract_shimcache_events(results: list[dict]) -> list[dict]:
    events = []
    for entry in results:
        if "error" in entry:
            continue
        path = entry.get("path", "unknown")
        ts = entry.get("last_modified")
        if is_valid_timestamp(ts):
            events.append({
                "timestamp": ts,
                "artifact": "Shimcache",
                "description": f"Executable on filesystem: {path} (last modified)",
                "source_file": "shimcache_results.json",
            })
    return events


def main():
    events = []
    events += extract_lnk_events(load_json(LNK_RESULTS))
    events += extract_prefetch_events(load_json(PREFETCH_RESULTS))
    events += extract_recycle_bin_events(load_json(RECYCLE_BIN_RESULTS))
    events += extract_shimcache_events(load_json(SHIMCACHE_RESULTS))

    events.sort(key=lambda e: e["timestamp"])

    os.makedirs(RESULTS_DIR, exist_ok=True)
    output_path = os.path.join(RESULTS_DIR, "timeline.json")
    with open(output_path, "w") as f:
        json.dump(events, f, indent=4)

    print(f"Timeline built: {len(events)} events written to {output_path}")


if __name__ == "__main__":
    main()
