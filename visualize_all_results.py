import json
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Charger le fichier JSON
with open("test.json", "r") as f:
    data = json.load(f)

# Créer un dossier de sortie si besoin
output_dir = "confusion_matrices"
os.makedirs(output_dir, exist_ok=True)

# Boucle sur toutes les matrices du JSON
for idx, entry in enumerate(data):
    confusion_data, model_version, segment_size = entry
    report, confusion = confusion_data

    plt.figure(figsize=(6, 5))
    sns.heatmap(confusion, annot=True, fmt='d', cmap="Blues",
                xticklabels=["nDoH/DoH Non-Malicious", "DoH Malicious"],
                yticklabels=["nDoH/DoH Non-Malicious", "DoH Malicious"])
    plt.title(f"Confusion Matrix (Model v{model_version}, Segment Size {segment_size})")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()

    # Nom de fichier unique
    filename = f"model_v{model_version}_seg{segment_size}.png"
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath)
    plt.close()

print(f"✅ {len(data)} matrices de confusion sauvegardées dans '{output_dir}/'")
