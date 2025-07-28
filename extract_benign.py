import os
import pandas as pd
import shutil
import argparse

def extract_benign_sessions(csv_path, output_json_dir="output", target_dir="benign_jsons"):
    # Charger le CSV
    df = pd.read_csv(csv_path)

    # Vérifier que la colonne 'suspicious' existe
    if "suspicious" not in df.columns:
        print("[!] No 'suspicious' column found in the CSV.")
        return

    # Filtrer les sessions bénignes
    benign_df = df[df["suspicious"] == False]
    if benign_df.empty:
        print("[!] No benign sessions found.")
        return

    # Sauvegarder en CSV
    benign_df.to_csv("benign_sessions.csv", index=False)
    print(f"[+] {len(benign_df)} benign sessions saved to benign_sessions.csv")

    # Créer dossier de destination
    os.makedirs(target_dir, exist_ok=True)

    # Copier les fichiers .json associés
    copied = 0
    for f in benign_df["filename"]:
        found = False
        for subfolder in ["doh", "ndoh"]:
            source_path = os.path.join(output_json_dir, subfolder, f)
            if os.path.exists(source_path):
                shutil.copy(source_path, os.path.join(target_dir, f))
                copied += 1
                found = True
                break
        if not found:
            print(f"[!] File not found for benign session: {f}")

    print(f"[+] {copied} JSON files copied to {target_dir}/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract benign sessions from DoHxP detection report.")
    parser.add_argument("-i", "--input", default="detection_report.csv", help="Input CSV file")
    parser.add_argument("-o", "--output", default="output", help="Root output directory (containing doh/ and ndoh/)")
    parser.add_argument("-t", "--target", default="benign_jsons", help="Target directory to copy benign JSON files")
    args = parser.parse_args()

    extract_benign_sessions(args.input, args.output, args.target)
