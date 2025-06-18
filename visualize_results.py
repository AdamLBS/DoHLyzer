import json
import matplotlib.pyplot as plt
import seaborn as sns

with open("test.json", "r") as f:
    data = json.load(f)

# Extraire la 1ère matrice de confusion
report, confusion = data[0][0]
model_version = data[0][1]
segment_size = data[0][2]

# Création du graphique
plt.figure(figsize=(6, 5))
sns.heatmap(confusion, annot=True, fmt='d', cmap="Blues",
            xticklabels=["nDoH/DoH Non-Malicious", "DoH Malicious"], yticklabels=["nDoH/DoH Non-Malicious", "DoH Malicious"])
plt.title(f"Confusion Matrix (Model v{model_version}, Segment Size {segment_size})")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.tight_layout()
plt.savefig("figure.png")
