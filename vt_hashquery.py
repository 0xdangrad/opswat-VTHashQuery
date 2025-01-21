"""
VT_HashQuery.py

Description:
This script scans all TXT and PDF files in a specified '.INPUT' directory, extracts unique hash strings (MD5, SHA1, SHA256), 
and queries VirusTotal (VT) for each hash using a provided API key. Due to VirusTotal's free tier rate limit, 
the script processes up to 4 hash queries every 65 seconds. 

The script outputs two result files in a newly created timestamped folder within the '.OUTPUT' directory:
1. VT_RESULTS_<timestamp>.TXT - A concise summary of VirusTotal verdicts for each hash, including how often 
   each hash appeared in the input files and a brief tally of detection results (e.g., malicious, undetected).
2. VERBOSE_VT_RESULTS_<timestamp>.TXT - A more detailed output, including the full VirusTotal response or 
   error messages for each hash.

Features:
- Processes all TXT and PDF files in the '.INPUT' folder, extracting and counting hash occurrences.
- Queries VirusTotal while handling API rate limits and errors gracefully.
- Summarizes VirusTotal results with a tally of detection verdicts.
- Saves both concise and verbose output files in an organized timestamped subfolder.

Usage:
- Place your TXT and PDF files in the '.INPUT' directory.
- Run the script, and the results will be saved in the '.OUTPUT' directory.
- Ensure you have a valid VirusTotal API key before running the script.

Note: This script requires the 'PyPDF2' and 'requests' libraries.
"""

import os
import re
import time
import requests
import PyPDF2
from datetime import datetime
from tabulate import tabulate
from collections import defaultdict, Counter

# Function to extract text from a PDF file
def extract_text_from_pdf(file_path):
    text = ""
    with open(file_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text()
    return text

# Function to extract hashes from text using regex and count occurrences
def extract_hashes_with_count(text):
    pattern = r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b'
    matches = re.findall(pattern, text)
    hash_counts = defaultdict(int)
    for match in matches:
        hash_counts[match] += 1
    return hash_counts

# Function to summarize VirusTotal results
def summarize_verdicts(vt_data):
    verdicts = Counter()
    if "data" in vt_data and "attributes" in vt_data["data"]:
        if "last_analysis_results" in vt_data["data"]["attributes"]:
            for result in vt_data["data"]["attributes"]["last_analysis_results"].values():
                verdicts[result["category"]] += 1
    return ", ".join([f"{key}: {count}" for key, count in verdicts.items()])

# Function to look up hashes on VirusTotal
def lookup_virustotal(hash_list, api_key):
    results = {}
    verbose_results = []
    url = "https://www.virustotal.com/api/v3/files/"

    for i in range(0, len(hash_list), 4):
        batch = hash_list[i:i + 4]
        for hash_value in batch:
            try:
                headers = {"x-apikey": api_key}
                response = requests.get(url + hash_value, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    results[hash_value] = summarize_verdicts(data)
                    verbose_results.append((hash_value, data))
                else:
                    results[hash_value] = f"Error: {response.status_code}"
                    verbose_results.append((hash_value, f"Error: {response.status_code}"))
            except Exception as e:
                results[hash_value] = f"Error: {str(e)}"
                verbose_results.append((hash_value, f"Error: {str(e)}"))

        if i + 4 < len(hash_list):
            time.sleep(65)  # Wait 65 seconds for the next batch

    return results, verbose_results

# Main script
def main():
    input_folder = ".INPUT"
    output_folder = ".OUTPUT"
    api_key = "YOUR_VT_API_KEY_HERE"  # Replace with your VirusTotal API key

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    all_hashes = defaultdict(lambda: defaultdict(int))

    # Read all TXT and PDF files from the .INPUT folder
    for file_name in sorted(os.listdir(input_folder)):  # Sort file names to ensure correct order
        file_path = os.path.join(input_folder, file_name)
        if file_name.lower().endswith(".txt"):
            with open(file_path, "r") as file:
                hashes = extract_hashes_with_count(file.read())
                for hash_value, count in hashes.items():
                    all_hashes[file_name][hash_value] += count
        elif file_name.lower().endswith(".pdf"):
            text = extract_text_from_pdf(file_path)
            hashes = extract_hashes_with_count(text)
            for hash_value, count in hashes.items():
                all_hashes[file_name][hash_value] += count

    # Collect all unique hashes for VirusTotal lookup
    unique_hashes = set()
    for file_hashes in all_hashes.values():
        unique_hashes.update(file_hashes.keys())

    # Perform VirusTotal lookups
    vt_results, verbose_results = lookup_virustotal(list(unique_hashes), api_key)

    # Prepare the results tables
    table = [["File", "Hash", "Count", "Result"]]
    for file_name in sorted(all_hashes.keys()):  # Sort file names to ensure correct order
        for hash_value, count in all_hashes[file_name].items():
            result = vt_results.get(hash_value, "No result found")
            table.append([file_name, hash_value, count, result])

    # Organize the output files into a new timestamped folder
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_subfolder = os.path.join(output_folder, timestamp)
    os.makedirs(output_subfolder, exist_ok=True)

    # Save the concise results to a TXT file
    concise_file_path = os.path.join(output_subfolder, f"VT_RESULTS_{timestamp}.TXT")
    with open(concise_file_path, "w") as output_file:
        output_file.write(tabulate(table, headers="firstrow"))

    # Save the verbose results to a TXT file
    verbose_file_path = os.path.join(output_subfolder, f"VERBOSE_VT_RESULTS_{timestamp}.TXT")
    with open(verbose_file_path, "w") as verbose_file:
        for hash_value, data in verbose_results:
            verbose_file.write(f"Hash: {hash_value}\n")
            verbose_file.write(f"Result: {data}\n")
            verbose_file.write("=" * 80 + "\n")

    # Display the concise results table
    print(tabulate(table, headers="firstrow"))

if __name__ == "__main__":
    main()
