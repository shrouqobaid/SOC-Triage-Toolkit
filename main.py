import os
import argparse
from dotenv import load_dotenv
from modules.vt_checker import check_ioc
from modules.reporter import generate_markdown_report

load_dotenv()

def main():
    parser = argparse.ArgumentParser(description="Automated SOC Alert Triage & Enrichment Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to the IOCs input file (e.g., iocs.txt)")
    parser.add_argument("-o", "--output", default="SOC_Triage_Report.md", help="Output report filename")
    
    args = parser.parse_args()
    input_file = args.file
    output_file = args.output

    print(f"[*] Starting Triage process using file: {input_file}")

    if not os.path.exists(input_file):
        print(f"[!] Error: File '{input_file}' not found.")
        return

    try:
        with open(input_file, "r") as f:
            iocs = [line.strip() for line in f if line.strip()]

    except PermissionError:
        print(f"[!] Error: Permission denied when reading '{input_file}'.")
        return

    except OSError as e:
        print(f"[!] Error reading input file: {e}")
        return

    if not iocs:
        print("[!] Error: Input file is empty.")
        return

    print(f"[*] Found {len(iocs)} IOCs to process.\n" + "="*50)
    
    all_results = []
    
    for ioc in iocs:
        print(f"[-] Checking IOC: {ioc} ...")
        result = check_ioc(ioc)
        all_results.append(result)
        
        if result["status"] == "Success":
            print(f"    [+] Malicious: {result['malicious']} | Suspicious: {result['suspicious']} | Harmless: {result['harmless']}")
        else:
            print(f"    [!] Status: {result['status']} - {result.get('message', '')}")
        print("-" * 50)

    generate_markdown_report(all_results, output_file)

if __name__ == "__main__":
    main()
