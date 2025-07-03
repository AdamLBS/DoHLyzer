import gzip
import ijson
import argparse
import json

def extract_segments(flow, segment_size):
    """
    Reproduit le même découpage que create_segments (sans normalisation ici).
    """
    clumps = flow["features"] if isinstance(flow, dict) and "features" in flow else flow

    # dépliage si mal imbriqué
    if isinstance(clumps[0], list):
        clumps = clumps[0]

    segments = []
    while len(clumps) < segment_size:
        clumps.append([-1, -1, -1, -1, 0])

    for i in range(len(clumps) - segment_size + 1):
        segments.append(clumps[i:i + segment_size])

    return segments

def main(misclassified_path, data_dir, segment_size):
    with open(misclassified_path) as f:
        errors = json.load(f)

    for error in errors:
        file = error["source_file"]
        index = error["local_index"]
        path = f"{data_dir}/{file}"

        print(f"\n🔎 Searching {path} for segment #{index}...")

        with gzip.open(path, 'rt') as f:
            items = ijson.items(f, 'item')
            all_segments = []
            for flow in items:
                segments = extract_segments(flow, segment_size)
                all_segments.extend(segments)
                if len(all_segments) > index:
                    print(f"\n✅ Found at index {index}:\n")
                    for i, vector in enumerate(all_segments[index]):
                        print(f"  Row {i + 1}: {vector}")
                    break
            else:
                print("❌ Index out of range in this file.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--misclassified", required=True, help="Path to misclassified_modelX_segY.json")
    parser.add_argument("--data-dir", default="./sample_data", help="Directory where doh/ndoh json.gz are")
    parser.add_argument("--segment-size", type=int, required=True, help="Segment size used during training")
    args = parser.parse_args()

    main(args.misclassified, args.data_dir, args.segment_size)
