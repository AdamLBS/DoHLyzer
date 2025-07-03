import os
import json
import gzip

# Dossiers
MISCLASSIFIED_DIR = "./missclassified"
DATA_DIR = "./output"
OUTPUT_FILE = "enriched_misclassified.json"

# Cache des fichiers source
cached_sources = {}

def load_source_file(filename):
    if filename not in cached_sources:
        path = os.path.join(DATA_DIR, filename)
        with gzip.open(path, "rt") as f:
            cached_sources[filename] = json.load(f)
    return cached_sources[filename]

def extract_features_and_meta(flow):
    # Format 1 : dictionnaire
    if isinstance(flow, dict):
        return flow.get("features"), flow.get("meta")

    # Format 2 : [features, meta] dans une liste
    if isinstance(flow, list) and len(flow) == 2:
        return flow[0], flow[1]

    # Sinon : erreur
    raise ValueError("Unknown flow format")

def enrich_all_misclassified():
    enriched = []

    for file in os.listdir(MISCLASSIFIED_DIR):
        if not file.endswith(".json"):
            continue

        with open(os.path.join(MISCLASSIFIED_DIR, file), "r") as f:
            entries = json.load(f)

        for entry in entries:
            source_file = entry["source_file"]
            local_index = entry["local_index"]

            try:
                data = load_source_file(source_file)
                flow = data[local_index]
                features, meta = extract_features_and_meta(flow)

                enriched_entry = {
                    "index": entry["index"],
                    "true_label": entry["true_label"],
                    "predicted_label": entry["predicted_label"],
                    "source_file": source_file,
                    "local_index": local_index,
                    "features": features,
                    "meta": meta
                }
                enriched.append(enriched_entry)
            except Exception as e:
                print(f"[!] Error on {source_file}[{local_index}]: {e}")

    with open(OUTPUT_FILE, "w") as out_f:
        json.dump(enriched, out_f, indent=2)

    print(f"[✓] Exported {len(enriched)} enriched entries to '{OUTPUT_FILE}'.")

if __name__ == "__main__":
    enrich_all_misclassified()
