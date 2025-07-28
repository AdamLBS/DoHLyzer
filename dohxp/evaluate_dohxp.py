import os
import json
from pathlib import Path
from sklearn.metrics import classification_report

# Seuils de DoHxP
PAYLOAD_THRESHOLD = 200
FREQ_THRESHOLD = 100
VOLUME_THRESHOLD = 7500

def apply_dohxp_detection(features):
    total_packets = sum(f[3] for f in features)
    total_bytes = sum(f[2] for f in features)
    duration = sum(f[1] for f in features)

    if total_packets == 0 or duration == 0:
        return False  # pas assez de données

    avg_packet_size = total_bytes / total_packets
    freq = total_packets / duration if duration > 0 else 0

    return (
        avg_packet_size > PAYLOAD_THRESHOLD or
        freq > FREQ_THRESHOLD or
        total_bytes > VOLUME_THRESHOLD
    )

def evaluate_dohxp_on_folder(folder_path):
    y_true = []
    y_pred = []
    total = 0

    for file in Path(folder_path).rglob("*.json"):
        with open(file, 'r') as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"Erreur lecture fichier {file}: {e}")
                continue

        for flow in data:
            features = flow.get("features", [])
            meta = flow.get("meta", {})
            if not features or "malicious" not in meta:
                continue

            true_label = meta["malicious"]
            detected = apply_dohxp_detection(features)

            y_true.append(true_label)
            y_pred.append(detected)
            total += 1

    print(f"\nTotal flows analysés : {total}\n")
    print(classification_report(y_true, y_pred, target_names=["Benign", "Malicious"]))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", required=True, help="Dossier contenant les fichiers .json")
    args = parser.parse_args()

    evaluate_dohxp_on_folder(args.directory)
