import os
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_dohlyzer(pcap_path, output_path, mode, python_exec):
    command = [
        python_exec, "-m", "meter.dohlyzer",
        "-f", pcap_path,
        "-c" if mode == "flow" else "-s",
        output_path
    ]
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[✔] {os.path.basename(pcap_path)} processed.")
    except subprocess.CalledProcessError as e:
        print(f"[✘] Error processing {pcap_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Multithreaded batch runner for meter.dohlyzer")
    parser.add_argument("input_dir", help="Path to folder containing .pcap files")
    parser.add_argument("output_dir", help="Folder to save output CSV/JSON files")
    parser.add_argument("--mode", choices=["flow", "sequence"], required=True,
                        help="flow: output CSV per file, sequence: output JSON directory")
    parser.add_argument("--python_exec", default="python3", help="Python executable to use (default: python3)")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel threads (default: 4)")
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input_dir)
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    pcap_files = [f for f in os.listdir(input_dir) if f.endswith(".pcap")]
    if not pcap_files:
        print("No .pcap files found in the input directory.")
        return

    print(f"Processing {len(pcap_files)} files with {args.workers} workers...\n")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for pcap_file in pcap_files:
            pcap_path = os.path.join(input_dir, pcap_file)
            output_path = (
                os.path.join(output_dir, f"{os.path.splitext(pcap_file)[0]}.csv")
                if args.mode == "flow"
                else output_dir
            )
            futures.append(executor.submit(run_dohlyzer, pcap_path, output_path, args.mode, args.python_exec))

        for future in as_completed(futures):
            _ = future.result()  # catch exceptions if any

if __name__ == "__main__":
    main()
