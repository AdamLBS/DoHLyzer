import json
import gzip
import os

input_dir = "output/doh"
output_path = "output/doh.json.gz"

all_data = []

for filename in os.listdir(input_dir):
    if filename.endswith(".json"):
        with open(os.path.join(input_dir, filename), "r") as f:
            data = json.load(f)
            all_data.append(data)

with gzip.open(output_path, "wt", encoding="utf-8") as f:
    json.dump(all_data, f)
