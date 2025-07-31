import os
import argparse
from time import sleep, time
from datetime import datetime
from zipfile import ZipFile 
import threading
import configparser
from queue import Queue

try:
    from termcolor import colored
except ModuleNotFoundError:
    exit("Missing Dependencies! Please ensure you install all dependencies from the 'requirements.txt' file")
try:
    from modules import pe_analysis
    from modules import virus_total
    from modules import yara_analysis
    from modules import analysis_report
    from modules import ai_verdict
    from modules import ascii_art
except ModuleNotFoundError:
    exit("Custom modules not found. Please ensure you have all necessary Morpheus modules!")

DEFAULT_RULE_PATH = os.path.join("yara_rules", "external_yara_rules", "default_built_in_rules")

# Rate limiting for VirusTotal API
API_CALLS = {}  # Tracks calls per API key
API_CALLS_LOCK = threading.Lock()
LAST_RESET = time()

# Program Intro Banner
def startup_banner():
    banner = colored(ascii_art.morpheus_banner(), "red", attrs=["bold"])  
    
    options = """
Morpheus V2 - Malware Analysis Framework
Use command-line arguments to perform scans:
  -h, --help                Show this help message and exit
  --yara-scan               Perform YARA scan
  --vt-scan                 Perform VirusTotal scan
  -f, --file <path>         Path to a single file to scan
  -d, --directory <path>    Path to a directory to scan
  --url <url>               URL to scan (vt-scan only)
  --hash-algo <md5|sha1|sha256>  Hashing algorithm for file (default: sha256)
  --pdf                     Generate PDF report (yara-scan or vt-scan for malicious samples)
"""
    print(banner + options)

# Redirects to scan banner
def menu_switch(choice):
    print(f"Starting {choice} scan ...")
    sleep(1)
    
    os.system("cls") if os.name == "nt" else os.system("clear")
    if choice == "virus_total":
        print(colored(ascii_art.virustotal_banner(), "cyan", attrs=["bold"]))
    else:
        print(colored(ascii_art.scan_banner(), "red", attrs=["bold"]))
    
    print("\n")

# Load API keys from config file
def load_api_keys():
    config = configparser.ConfigParser()
    config.read('api_config.ini')
    try:
        keys = config['VirusTotal']['api_keys'].split(',')
        return [key.strip() for key in keys if key.strip()]
    except KeyError:
        print(colored("[-] Error: 'api_config.ini' missing or invalid. Please create with [VirusTotal] section and 'api_keys' field.", "red"))
        exit(1)

# Rate limiting check
def check_rate_limit(api_key):
    global API_CALLS, LAST_RESET
    with API_CALLS_LOCK:
        current_time = time()
        # Reset counts every minute
        if current_time - LAST_RESET >= 60:
            API_CALLS.clear()
            LAST_RESET = current_time
        
        API_CALLS.setdefault(api_key, 0)
        if API_CALLS[api_key] >= 4:
            sleep_time = 60 - (current_time - LAST_RESET)
            if sleep_time > 0:
                print(colored(f"[-] Rate limit reached for API key {api_key}. Waiting {sleep_time:.2f} seconds.", "yellow"))
                sleep(sleep_time)
                API_CALLS.clear()
                LAST_RESET = time()
                API_CALLS[api_key] = 0
        API_CALLS[api_key] += 1

# Start VirusTotal scan
def virus_total_scan(api_key, data, choice, hash_algo="sha256"):
    check_rate_limit(api_key)
    virus_total_object = virus_total.VirusTotalAPI(choice, data, api_key)
    client_object, status_message = virus_total_object.connect_to_endpoint()
    if status_message == "api_fail":
        print(colored("API Error: The 'vt' library encountered an issue. Please ensure your API key is valid.", "red"))
        return False, None
    elif status_message == "general_fail":
        print(colored("General Error: A failure occurred while connecting to the API.", "red"))
        return False, None
    
    virus_total_object.client_obj = client_object
    api_request_string = virus_total_object.craft_api_request()
    output, function_status = virus_total_object.send_api_request_using_vt(api_request_string)
    if function_status == "api_fail":
        print(colored(virus_total_object.parse_API_error(output), "red"))
        return False, None
    elif function_status == "general_fail":
        print(colored(output, "red"))
        return False, None
    
    results = virus_total_object.parse_API_output(output)
    return True, results

# Hash file for VirusTotal scan
def hash_file(path, hash_algo="sha256"):
    virus_total_object = virus_total.VirusTotalAPI()
    if hash_algo not in ["md5", "sha256", "sha1"]:
        hash_algo = "sha256"
    
    try:
        file_data = load_file(path)
        return virus_total_object.hash_file(file_data, hash_algo)
    except Exception as e:
        print(colored(f"[-] Error hashing file '{path}': {str(e)}", "red"))
        return None

# Parse hash output
def parse_hash_output(output):
    message = None
    if not output:
        message = "[-] An unknown error occurred: no object returned from the hashing method."
    elif output == "hashing_error":
        message = "[-] Hashing error detected. Please ensure the data is valid."
    elif output == "hash_digest_error":
        message = "[-] Hash digest error: the hash object was created, but the final output could not be parsed."
    if message:
        print(colored(message, "red"))
        return False
    return True

# Load file
def load_file(user_path):
    if not os.path.exists(user_path.strip()):
        raise FileNotFoundError(f"The file '{user_path}' does not exist!")
    
    with open(user_path, "rb") as file:
        return file.read()

# YARA scan for a single file
def default_yara_scan(file_path, pdf_flag):    
    print(colored(f"\nScanning file: {file_path}", "cyan"))
    print("_" * (37 + len(file_path)))
    print("\n")
    
    pe_file_analysis(file_path)
    
    yara_matches = []
    for scan_type in ["file_analysis", "malware_scan"]:                
        yara_base_instance = yara_analysis.BaseDetection(file_path, scan_type)
        time_snapshot = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        
        if scan_type == "file_analysis":
            custom_message("file analysis", time_snapshot)
        else:
            print("\n")
            custom_message("malware analysis", time_snapshot)    
        
        try:
            yara_base_instance.parse_yara_rules(yara_base_instance)
            yara_matches.extend(yara_base_instance.yara_matches)
        except Exception as e:
            print(colored(f"[-] YARA scan error for {file_path}: {str(e)}", "red"))
            return False
    
    converted_output = format_yara_output(yara_matches)
    
    if pdf_flag:
        file_name = os.path.basename(file_path)
        generate_pdf_report(file_name, converted_output)
    
    print("\n")
    custom_message("AI verdict", "(Verify independently)")
    verdict_error_output = generate_ai_verdict(converted_output)
    
    if verdict_error_output:
        print(colored(verdict_error_output, "red", attrs=["bold"]))
    
    return True

# YARA scan for a directory
def scan_directory(dir_path, pdf_flag):
    if not os.path.isdir(dir_path):
        print(colored(f"[-] The directory '{dir_path}' does not exist! Skipping.", "red"))
        return False
    
    print(colored(f"Scanning directory: {dir_path}", "yellow"))
    success = False
    for root, _, files in os.walk(dir_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                if default_yara_scan(file_path, pdf_flag):
                    success = True
            except Exception as e:
                print(colored(f"[-] Error scanning file '{file_path}': {str(e)}", "red"))
                continue
    return success

# VirusTotal scan for a directory with multiple API keys
def scan_directory_vt(dir_path, api_keys, hash_algo, pdf_flag):
    if not os.path.isdir(dir_path):
        print(colored(f"[-] The directory '{dir_path}' does not exist! Skipping.", "red"))
        return False
    
    print(colored(f"Scanning directory with VirusTotal: {dir_path}", "yellow"))
    success = False
    file_queue = Queue()
    
    # Collect all files
    for root, _, files in os.walk(dir_path):
        for file_name in files:
            file_queue.put(os.path.join(root, file_name))
    
    def worker(api_key):
        while not file_queue.empty():
            try:
                file_path = file_queue.get()
                print(colored(f"\nScanning file: {file_path} with API key {api_key[:4]}...", "cyan"))
                data = hash_file(file_path, hash_algo)
                if data and parse_hash_output(data):
                    print(colored(f"\n✔ Successfully hashed file -> {data}", "green"))
                    print(f"{'-' * 100}\n")
                    scan_success, results = virus_total_scan(api_key, data, "files", hash_algo)
                    if scan_success:
                        success = True
                        if pdf_flag and results and results.get('verdict') in ["Deemed Likely Malicious", "Deemed Possibly Malicious"]:
                            file_name = os.path.basename(file_path)
                            generate_pdf_report(file_name, results, is_vt=True)
            except Exception as e:
                print(colored(f"[-] Error scanning file '{file_path}': {str(e)}", "red"))
            finally:
                file_queue.task_done()
    
    threads = []
    for api_key in api_keys:
        t = threading.Thread(target=worker, args=(api_key,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    return success

# Generate PDF report
def generate_pdf_report(file_name, results, is_vt=False):
    pdf_base_instance = analysis_report.ReportOutput(file_name, results)
    creation_result = pdf_base_instance.pdf_main_content()
    if isinstance(creation_result, str) and "Error" in creation_result:
        print(colored(f"[-] Skipped PDF Creation Due to Error - {creation_result}", "red"))
    else:
        print(colored("[+] Output Converted to a PDF Document - Document Found in 'reports' Directory", "green"))

# Format YARA output
def format_yara_output(yara_results):        
    converted_output = {
        "General File Analysis YARA Output": [],
        "Malware Analysis YARA Output": [],
    }
    
    for match in yara_results:
        if hasattr(match, 'meta') and match.meta.get("author") in ["Morpheus", "yarGen Rule Generator Morpheus"]:
            converted_output["General File Analysis YARA Output"].append(match)
        else:
            converted_output["Malware Analysis YARA Output"].append(match)
    
    return converted_output

# Send API request and return AI verdict
def generate_ai_verdict(yara_match_results):
    ai_verdict_object = ai_verdict.AIVerdict(yara_match_results)
    json_payload = ai_verdict_object.generate_api_request()
    request_output, request_status = ai_verdict_object.send_api_request(json_payload) 
    if request_status == "fail":
        return request_output
    
    if ai_verdict_object.supports_advanced_formatting():
        ai_verdict_object.format_string_to_markdown(request_output)
    else:
        print(request_output.strip().replace("```", "").replace("**", ""))
    return None

# Handle PE file analysis
def pe_file_analysis(file_path):
    pe_obj = pe_analysis.ExecutableAnalysis(file_path)
    
    if pe_obj.is_pe_file():
        custom_message("portable executable analysis")
    else:
        return
    
    print(colored(pe_obj.is_pe_file(), "green"))
    print(">", pe_obj.check_signature_presence())
    print(f"> File Architecture : {pe_obj.get_architecture()}" if pe_obj.get_architecture() != "Unidentified" else "> Unidentified Architecture")
    
    entropy = pe_obj.get_section_entropy()
    print("\nEntropy Information :")
    for key, value in entropy.items():
        print(f"{key.ljust(20)}: {value}")
    
    suspicious_sections = pe_obj.detect_any_suspicious_sections()
    if suspicious_sections:
        print("\nPotentially Suspicious Section/s Found :")
        for section in suspicious_sections:
            print(f"\t> {section}")
    
    entry_imports = pe_obj.identify_imports()
    if entry_imports:
        print(f"\nEntry Imports Identified : {', '.join(entry_imports)}")
    
    suspicious_api_calls = pe_obj.detect_suspicious_imports()
    if suspicious_api_calls:
        print("\nPotentially Suspicious API Calls (Presence does not confirm malicious intent) :")
        for name, location in suspicious_api_calls.items():
            print(f"\t> Suspicious API : '{name}' found in '{location}'")
    
    print("\n\n")

# Display banner when scanning
def custom_message(message, custom_message="", time=None):
    if time:
        full_message = f"Started {message} scan on {time}"
    else:
        full_message = f"Started {message} scan {custom_message}"
    
    print("-" * len(full_message))
    print(colored(full_message, attrs=["bold"]))
    print("-" * len(full_message))

# Extract zipped YARA files
def extract_all_zip_contents():
    zipped_path = DEFAULT_RULE_PATH + ".zip"
    
    if os.path.exists(zipped_path):
        try:
            with ZipFile(zipped_path, 'r') as zipped_file: 
                zipped_file.extractall(path=os.path.join("yara_rules", "external_yara_rules")) 
            os.remove(zipped_path)
        except Exception as e:
            print(colored(f"[-] Error extracting or removing YARA rules zip: {str(e)}", "red"))

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Morpheus V2 - Malware Analysis Framework", add_help=False)
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    parser.add_argument("--yara-scan", action="store_true", help="Perform YARA scan")
    parser.add_argument("--vt-scan", action="store_true", help="Perform VirusTotal scan")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="Path to a single file to scan")
    group.add_argument("-d", "--directory", help="Path to a directory to scan")
    parser.add_argument("--url", help="URL to scan (vt-scan only)")
    parser.add_argument("--hash-algo", choices=["md5", "sha1", "sha256"], default="sha256", help="Hashing algorithm for file (default: sha256)")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF report (yara-scan or vt-scan for malicious samples)")
    
    args = parser.parse_args()
    
    if not (args.yara_scan or args.vt_scan):
        startup_banner()
        parser.error("At least one of --yara-scan or --vt-scan must be specified")
    
    if (args.file or args.directory) and args.url:
        parser.error("--url cannot be combined with --file or --directory")
    
    return args

# Handle menu arguments
def handle_menu_arguments():
    args = parse_arguments()
    extract_all_zip_contents()
    
    # Validate YARA rules for yara-scan
    yara_success = True
    if args.yara_scan:
        yara_rule_path = os.path.join(os.getcwd(), "yara_rules", "external_yara_rules")
        if not os.path.exists(yara_rule_path) or not os.listdir(yara_rule_path):
            print(colored("[-] No YARA rules found in 'yara_rules/external_yara_rules'. Please run 'setup.py' to populate rules.", "red"))
            yara_success = False
        elif os.path.exists(DEFAULT_RULE_PATH):
            print(colored("[!] Using Default Yara Rules. Results may be limited - Consider running 'setup.py'.", "yellow"))
    
    # Perform YARA scan
    if args.yara_scan and yara_success:
        menu_switch("yara")
        if args.file:
            if os.path.isfile(args.file):
                default_yara_scan(args.file, args.pdf)
            else:
                print(colored(f"[-] The file '{args.file}' does not exist! Aborting YARA scan.", "red"))
        elif args.directory:
            scan_directory(args.directory, args.pdf)
        else:
            print(colored("[-] No file or directory specified for YARA scan!", "red"))
    
    # Perform VirusTotal scan
    if args.vt_scan:
        api_keys = load_api_keys()
        if not api_keys:
            print(colored("[-] No valid API keys found in 'api_config.ini'. Aborting VirusTotal scan.", "red"))
            return
        
        menu_switch("virus_total")
        if args.url:
            print(colored(f"\n✔ Successfully added URL -> {args.url}", "green"))
            print(f"{'-' * 100}\n")
            # Use the first API key for URL scans
            scan_success, results = virus_total_scan(api_keys[0], args.url, "urls", args.hash_algo)
            if scan_success and args.pdf and results and results.get('verdict') in ["Deemed Likely Malicious", "Deemed Possibly Malicious"]:
                generate_pdf_report("url_scan", results, is_vt=True)
        elif args.file:
            if os.path.isfile(args.file):
                data = hash_file(args.file, args.hash_algo)
                if data and parse_hash_output(data):
                    print(colored(f"\n✔ Successfully hashed file -> {data}", "green"))
                    print(f"{'-' * 100}\n")
                    scan_success, results = virus_total_scan(api_keys[0], data, "files", args.hash_algo)
                    if scan_success and args.pdf and results and results.get('verdict') in ["Deemed Likely Malicious", "Deemed Possibly Malicious"]:
                        file_name = os.path.basename(args.file)
                        generate_pdf_report(file_name, results, is_vt=True)
            else:
                print(colored(f"[-] The file '{args.file}' does not exist! Aborting VirusTotal scan.", "red"))
        elif args.directory:
            scan_directory_vt(args.directory, api_keys, args.hash_algo, args.pdf)
        else:
            print(colored("[-] No file, directory, or URL specified for VirusTotal scan!", "red"))

# Main function
def main():
    startup_banner()
    try:
        handle_menu_arguments()
    except KeyboardInterrupt:
        exit("\n[!] User Interrupt. Program Exited Successfully")

if __name__ == "__main__":
    main()