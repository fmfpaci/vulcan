# ==================================================================================================
# SCRIPT: VULNERABILITY_EXTRACTOR.PY
#
# DESCRIPTION:
# This script automates the process of extracting Common Weakness Enumeration (CWE) identifiers
# from a collection of text files containing vulnerability analyses. It uses a Generative AI model
# (specified by MODEL_NAME) to analyze the text and return structured data.
#
# WORKFLOW:
# 1.  Dependency Check: Verifies that all required Python libraries are installed before execution.
# 2.  Initialization: Sets up paths, API keys, and model configurations.
# 3.  File Processing (Phase 1): Iterates through specified "prompt" directories, reads each text file,
#     and calls the Generative AI model to extract CWEs. Results are logged.
# 4.  Retry Mechanism (Phase 2): If any files fail during Phase 1 (e.g., due to API errors),
#     the script attempts to re-process them multiple times.
# 5.  Report Generation (Phase 3): Consolidates all successful results into separate, clean
#     Excel reports for each prompt. It also performs data cleanup, like correcting CWE typos.
# 6.  Final Summary (Phase 4): Prints a summary of the entire operation, highlighting the number
#     of successfully processed files, recovered files, and any files that permanently failed.
#
# USAGE:
# Run from the command line, optionally specifying which prompt directories to analyze.
# > python your_script_name.py -p 1 2
# > python your_script_name.py --test-dir "/path/to/custom/dataset" -p 1
# ==================================================================================================

import os
import pandas as pd
import re
import xml.etree.ElementTree as ET
import argparse
import time

# ==================================================================================================
# I. DEPENDENCY MANAGEMENT & INITIALIZATION
# ==================================================================================================

# These modules are imported here to support the dependency checker itself.
# The script-specific dependencies (like tqdm, google.generativeai) are checked below.
import sys
import importlib

def check_dependencies():
    """
    Verifies that all required third-party libraries are installed.

    This function iterates through a predefined dictionary of necessary modules.
    It uses 'importlib' to programmatically check for the presence of each module.
    If a module is not found, its package name is added to a list of missing
    dependencies. If this list is not empty after checking, a user-friendly error
    message is displayed with instructions on how to install them, and the script
    exits.
    """
    # A dictionary mapping the module name (for import) to the package name (for pip install).
    dependencies = {
        "pandas": "pandas",
        "google.generativeai": "google-generativeai",
        "tqdm": "tqdm",
        "openpyxl": "openpyxl"  # Essential for the df.to_excel() function to work.
    }
    
    missing_deps = []
    
    print("Verifying script dependencies...")
    for module_name, package_name in dependencies.items():
        try:
            # Attempt to import the module.
            importlib.import_module(module_name)
        except ImportError:
            # If the import fails, add the package to the list of missing ones.
            missing_deps.append(package_name)
            
    if missing_deps:
        # If any dependencies are missing, print a detailed error message and exit.
        print("\n" + "❌" * 20)
        print("❌ CRITICAL ERROR: Missing Dependencies.")
        print("   Before running the script, you must install the following libraries:")
        for pkg in missing_deps:
            print(f"     - {pkg}")
        
        # Provide a convenient, single command for the user to copy and paste.
        install_command = f"pip install {' '.join(missing_deps)}"
        print("\n   You can install them all with this single command:")
        print(f"   > {install_command}")
        print("❌" * 20 + "\n")
        sys.exit(1) # Exit the script with a non-zero status code to indicate an error.
    
    print("✅ All required dependencies are installed.")
    print("-" * 60)

# The actual import of third-party libraries is deferred until after the check.
# This ensures that the script doesn't crash with an ImportError before our friendly
# error message can be displayed.
try:
    import google.generativeai as genai
    from tqdm import tqdm
except ImportError:
    # This block should theoretically not be reached if check_dependencies() is called first,
    # but it serves as a robust fallback.
    pass


# ==================================================================================================
# II. SCRIPT CONFIGURATION
# Global constants that control the script's behavior.
# ==================================================================================================

# Default base directory where datasets are located. This is used if the --test-dir argument is not provided.
DEFAULT_MODEL_DIR = ""
# The specific dataset folder name within the base directory.
DATASET_DIR = "PrimeVul"
# Path to the CWE XML file, used to validate the existence of a CWE ID.
XML_PATH = "data-analysis/cwec_v4.17.xml"
# The specific Generative AI model to be used for the analysis.
MODEL_NAME = "gemini-2.5-flash"

# --- RETRY MECHANISM ---
# Defines the behavior for handling transient errors during API calls.
# Maximum number of times to retry processing a single file if it fails.
MAX_RETRIES = 5
# Number of seconds to wait between consecutive retry attempts for a failed file.
RETRY_DELAY_SECONDS = 5

# --- API CONFIGURATION ---
# The API key for the Generative AI service.
API_KEY = "INSERT YOUR API KEY HERE"

# NOTE: The validation and configuration of the API key and model are performed inside the main()
# function to ensure they only run after the dependency check has passed successfully.


# ==================================================================================================
# III. HELPER FUNCTIONS
# Reusable functions that perform specific tasks within the script.
# ==================================================================================================

def cwe_exists(xml_file, cwe_id):
    """
    Checks if a given CWE ID is a valid entry in the official CWE XML file.

    Args:
        xml_file (str): The file path to the CWE XML data dump (e.g., 'cwec_v4.17.xml').
        cwe_id (str): The CWE identifier to validate (e.g., '20' for 'CWE-20').

    Returns:
        bool: True if the CWE ID exists in the file, False otherwise.
              Returns False if the XML file cannot be found or parsed.
    """
    try:
        # Parse the entire XML file into an ElementTree object.
        tree = ET.parse(xml_file)
        root = tree.getroot()
        # Define the XML namespace used in the CWE file to properly query elements.
        namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        # Use a generator expression with any() for an efficient search. It stops as soon
        # as a match is found. It iterates through all 'Weakness' tags and checks their 'ID' attribute.
        return any(w.attrib.get('ID') == str(cwe_id) for w in root.iterfind('.//cwe:Weakness', namespace))
    except (FileNotFoundError, ET.ParseError) as e:
        # Handle cases where the XML file is missing or malformed.
        print(f"❌ ERROR: Problem with the CWE XML file '{xml_file}': {e}")
        return False

def call_llm_for_extraction(text_chunk, model):
    """
    Sends a text chunk to the configured Generative AI model and asks it to extract CWE data.

    Args:
        text_chunk (str): The content of the vulnerability analysis file to be processed.
        model (genai.GenerativeModel): The initialized generative model instance.

    Returns:
        tuple: A tuple containing two elements:
               - str: The raw text response from the model.
               - str or None: An error message if the call failed, otherwise None.
    """
    # The prompt is carefully structured to guide the model towards the desired output format.
    prompt = f"""
You are an assistant that extracts structured data from text.
Given the following vulnerability analysis, extract:
1. A list of CWE identifiers found (like CWE-119, CWE-20), or "NOT VULNERABLE" if none.
Return your result in this exact format:
CWE: <CWE-IDs separated by semicolons> OR NOT VULNERABLE
Text:
{text_chunk}
"""
    try:
        # Call the model's generate_content method with the crafted prompt.
        response = model.generate_content(prompt)
        # The response object may have no 'parts' if it was blocked by safety filters.
        if not response.parts:
            return None, "API call was blocked or returned an empty response (likely a safety filter)."
        # If successful, return the clean text and no error message.
        return response.text.strip(), None
    except Exception as e:
        # Catch any other exception during the API call (e.g., network issues, invalid API key).
        return None, f"An exception occurred during the API call: {e}"

def correct_cwe_typos(cell_content):
    """
    Standardizes common typos found in CWE identifiers to the 'CWE-XXX' format.

    For example, it corrects 'C-123' or 'CW-45' to 'CWE-123' and 'CWE-45'.

    Args:
        cell_content (str): The string content from the DataFrame cell which may contain typos.

    Returns:
        str: The corrected string, or the original content if it was not a string.
    """
    if not isinstance(cell_content, str):
        return cell_content
    # A regular expression finds patterns starting with 'C', followed by optional letters and a hyphen,
    # and then digits. It replaces the prefix with 'CWE-'. It is case-insensitive.
    corrected_content = re.sub(r'C[A-Z]*-(\d+)', r'CWE-\1', cell_content, flags=re.IGNORECASE)
    return corrected_content

def process_single_file(input_file_path, model):
    """
    Orchestrates the processing of a single text file from reading to result parsing.

    This function performs the following steps:
    1. Reads the content of the specified file.
    2. Calls the LLM via `call_llm_for_extraction`.
    3. Parses the raw response from the LLM to isolate the CWE data.
    4. Determines the "ground truth" CWE from the file's name for later comparison.
    5. Compiles all extracted information into a structured dictionary.

    Args:
        input_file_path (str): The full path to the text file to be processed.
        model (genai.GenerativeModel): The initialized generative model instance.

    Returns:
        tuple: A tuple containing three elements:
               - dict or None: A dictionary with the results ('File Name', 'Found CWE', 'Actual CWE').
               - str or None: The clean response string from the model (the part after "CWE:").
               - str or None: An error message if any step failed, otherwise None.
    """
    file_only = os.path.basename(input_file_path)
    
    # Step 1: Read the file content with error handling.
    try:
        with open(input_file_path, 'r', encoding='utf8') as file:
            text = file.read()
    except (IOError, OSError) as e:
        return None, None, f"Could not read file: {e}"

    # Step 2: Call the LLM and handle potential failures.
    response_raw, error_msg = call_llm_for_extraction(text, model)
    if response_raw is None:
        return None, None, f"API call failed: {error_msg}"

    # Step 3: Parse the raw LLM response to find the line with the CWE data.
    found_cwe_clean = "NOT VULNERABLE" # Default value if the line isn't found.
    for line in response_raw.splitlines():
        if line.lower().strip().startswith("cwe:"):
            # Extract the content after the "CWE:" prefix.
            found_cwe_clean = line.split(":", 1)[1].strip()
            break # Stop searching once the line is found.

    # ==================== INIZIO DELLA MODIFICA ====================
    # Step 4: Determina il "ground truth" CWE basandosi sul nome del file.
    actual_cwe = "NOT VULNERABLE"
    if "not_vulnerable" not in input_file_path.lower():
        # Usa re.findall per trovare TUTTE le occorrenze di 'CWE-XXX' nel percorso del file.
        # Questo risolve il problema di trovare solo la prima vulnerabilità.
        matches = re.findall(r"CWE-\d+", input_file_path)
        
        if matches:
            # Se vengono trovate una o più corrispondenze, uniscile con un punto e virgola.
            # Esempio: ['CWE-20', 'CWE-119'] diventa 'CWE-20;CWE-119'
            actual_cwe = ';'.join(matches)
        else:
            # Se non ci sono CWE nel nome e non è 'not_vulnerable', lo segna come sconosciuto.
            actual_cwe = "UNKNOWN"
    # ===================== FINE DELLA MODIFICA =====================

    # Step 5: Assemble the final, structured result.
    result_dict = {"File Name": file_only, "Found CWE": found_cwe_clean.upper(), "Actual CWE": actual_cwe}
    return result_dict, found_cwe_clean, None


def main():
    """
    The main execution function that orchestrates the entire workflow.
    """
    # --- API and Model Initialization ---
    # This happens here to ensure dependencies were successfully checked first.
    if not API_KEY or "INSERT" in API_KEY:
        print("❌ CRITICAL ERROR: API Key not found or invalid. Please set the API_KEY variable in the script.")
        return # Stop execution if the API key is not set.
    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel(MODEL_NAME, generation_config={"temperature": 0.1})
    safe_model_name = MODEL_NAME.replace('.', '_') # Create a filename-safe version of the model name.

    # --- Command-Line Argument Parsing ---
    # Sets up how users can interact with the script from the terminal.
    parser = argparse.ArgumentParser(
        description="Extracts CWE vulnerabilities from text files, handles API failures with retries, and consolidates results into Excel reports.",
        formatter_class=argparse.RawTextHelpFormatter # Allows for multi-line help messages.
    )
    parser.add_argument("-td", "--test-dir", type=str, required=False, help="Full path to the dataset folder.")
    parser.add_argument(
        "-p", "--prompts",
        nargs='+',  # Allows for multiple values (e.g., -p 1 2 3).
        type=int,
        default=[1, 2, 3], # Default prompts to run if none are specified.
        help="Specify the prompt numbers to analyze (e.g., -p 1 3). Default: 1 2 3."
    )
    args = parser.parse_args()

    # --- Path and Input Setup ---
    # Ensure the list of prompts is unique and sorted.
    prompts_to_run = sorted(list(set(args.prompts)))

    # Determine the root dataset path, preferring the command-line argument over the default.
    if args.test_dir:
        dataset_path = args.test_dir
        print(f"📁 Mode: Analyzing the directory provided directly:\n   -> {dataset_path}")
    else:
        dataset_path = os.path.join(DEFAULT_MODEL_DIR, DATASET_DIR)
        print(f"📁 Mode: Using the constructed default path:\n   -> {dataset_path}")

    # Critical check: terminate if the dataset directory doesn't exist.
    if not os.path.isdir(dataset_path):
        print(f"\n❌ CRITICAL ERROR: The directory '{dataset_path}' does not exist. The script cannot continue.")
        return

    print(f"🔧 The following prompts will be analyzed: {', '.join(map(str, prompts_to_run))}")

    # ==============================================================================================
    # PHASE 1: MAIN PROCESSING LOOP
    # Iterates through each requested prompt, processes all its files, and logs results.
    # ==============================================================================================
    all_results = {} # A dictionary to hold results, keyed by prompt number.
    error_log = []   # A list to store information about any files that failed processing.

    # Iterate only over the prompts requested by the user.
    for i in prompts_to_run:
        all_results[i] = []  # Initialize the list for the current prompt's results.

        print("-" * 60)
        print(f"🚀 Starting processing for PROMPT {i}")

        # Construct the input and output directories for the current prompt.
        input_dir = os.path.join(dataset_path, f'split_responses_prompt_{i}')
        output_dir = os.path.join(dataset_path, f'parser_output_prompt_{i}')

        try:
            # Create the output directory if it doesn't already exist.
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(f"❌ ERROR: Could not create the output directory '{output_dir}': {e}")
            continue # Skip this prompt and move to the next one.

        # Check if the input directory for this prompt exists.
        if not os.path.isdir(input_dir):
            print(f"⚠️  The input folder '{input_dir}' does not exist. Skipping to the next prompt.")
            continue

        # Define the path for the raw text output log.
        output_text_path = os.path.join(output_dir, f"parser_{safe_model_name}_output_prompt_{i}.txt")

        try:
            # Open the text log file for writing.
            with open(output_text_path, 'w', encoding='utf-8') as text_out_file:
                # Get a list of all files in the input directory.
                file_list = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]

                # Use tqdm for a progress bar.
                progress_bar = tqdm(file_list, desc=f"Analyzing Prompt {i}", unit="file", ncols=100)
                for file_name in progress_bar:
                    full_path = os.path.join(input_dir, file_name)
                    # Process the single file.
                    result_data, clean_response, error_msg = process_single_file(full_path, model)

                    if result_data:
                        # If successful, store the dictionary and write to the text log.
                        all_results[i].append(result_data)
                        text_out_file.write(f"File: {result_data['File Name']}\nResponse: {clean_response}\n\n")
                    else:
                        # --- MODIFICATION START ---
                        # This block now prints the error immediately upon failure
                        # without disrupting the progress bar.
                        tqdm.write(
                            f"\n🔴 ERROR on file '{file_name}'. Reason: {error_msg}"
                        )
                        # --- MODIFICATION END ---
                        
                        # If failed, add the file to the error log for the retry phase.
                        error_log.append({"file": file_name, "full_path": full_path, "prompt_num": i, "reason": error_msg})
        except IOError as e:
            print(f"❌ ERROR: Could not write to the log file '{output_text_path}': {e}")
            continue # Skip to the next prompt if logging fails.

        print(f"📝 Text log for Prompt {i} saved in: {output_text_path}")
        print(f"🏁 Finished processing for PROMPT {i}. Results kept in memory for consolidation.")

    # ==============================================================================================
    # PHASE 2: FAILED FILE RECOVERY
    # Attempts to re-process any files that failed during the initial run.
    # ==============================================================================================
    print("-" * 60)
    permanently_failed = []
    recovered_count = 0

    if error_log:
        print(f"🔁 Starting recovery phase for {len(error_log)} failed files (max {MAX_RETRIES} retries per file)...")
        time.sleep(1) # A small delay to ensure the message is visible before the progress bar starts.

        for error_item in tqdm(error_log, desc="Attempting recovery", unit="file", ncols=100):
            recovered = False
            last_error = "N/A"

            # Loop up to MAX_RETRIES times for each failed file.
            for attempt in range(MAX_RETRIES):
                result_data, clean_response, error_msg = process_single_file(error_item['full_path'], model)

                if result_data:
                    # If recovery is successful...
                    prompt_num = error_item['prompt_num']
                    all_results[prompt_num].append(result_data) # Add the result to the main list.
                    recovered_count += 1
                    recovered = True

                    # Append the recovered result to its corresponding text log file.
                    output_dir = os.path.join(dataset_path, f'parser_output_prompt_{prompt_num}')
                    output_text_path = os.path.join(output_dir, f"parser_{safe_model_name}_output_prompt_{prompt_num}.txt")
                    try:
                        with open(output_text_path, 'a', encoding='utf-8') as text_out_file:
                            text_out_file.write("\n# --- RECOVERED --- #\n")
                            text_out_file.write(f"File: {result_data['File Name']}\nResponse: {clean_response}\n\n")
                    except IOError as e:
                        # tqdm.write allows printing messages without disrupting the progress bar.
                        tqdm.write(f"\n⚠️  ERROR: Could not append recovered result to text file {output_text_path}: {e}")

                    break # Exit the retry loop for this file on success.
                else:
                    # If it fails again, save the last error and wait before the next attempt.
                    last_error = error_msg
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY_SECONDS)

            # If the file was not recovered after all retries, log it as a permanent failure.
            if not recovered:
                error_item['reason'] = f"Failed after {MAX_RETRIES} attempts. Last error: {last_error}"
                permanently_failed.append(error_item)

        if recovered_count > 0:
            print(f"\n✅ Successfully recovered {recovered_count} files and added them to their reports.")

    # ==============================================================================================
    # PHASE 3: FINAL REPORT GENERATION
    # Consolidates all results into final Excel files, one for each prompt.
    # ==============================================================================================
    print("-" * 60)
    print("✍️  Writing final consolidated Excel reports...")

    # Iterate only over the prompts that were actually processed and have results.
    for i in all_results.keys():
        if not all_results[i]:
            print(f"⚠️  No results to write for Prompt {i}.")
            continue

        # Create a pandas DataFrame from the list of result dictionaries.
        df = pd.DataFrame(all_results[i])
        # Apply the typo correction function to the 'Found CWE' column.
        df['Found CWE'] = df['Found CWE'].apply(correct_cwe_typos)
        # Sort the report by file name for consistency.
        df.sort_values(by="File Name", inplace=True)

        output_dir = os.path.join(dataset_path, f'parser_output_prompt_{i}')
        output_excel_path = os.path.join(output_dir, f"vulnerability_{safe_model_name}_report_prompt_{i}.xlsx")

        try:
            # Write the DataFrame to an Excel file, excluding the pandas index.
            df.to_excel(output_excel_path, index=False)
            print(f"✅ Excel report for Prompt {i} generated successfully: {output_excel_path}")
        except ImportError:
            # This error is caught here specifically in case openpyxl was uninstalled mid-process.
            print(f"❌ ERROR (Prompt {i}): 'openpyxl' library not found. Please run: pip install openpyxl")
        except Exception as e:
            # Catch any other errors during file writing (e.g., permissions issues).
            print(f"❌ ERROR (Prompt {i}): Could not save the Excel file '{output_excel_path}': {e}")

    # ==============================================================================================
    # PHASE 4: FINAL SUMMARY
    # Prints a concluding summary of the script's execution.
    # ==============================================================================================
    print("-" * 60)
    print("📊 Final Summary 📊")

    if not error_log:
        print("🎉 Processing completed without any errors.")
    else:
        if recovered_count > 0:
            print(f"👍 {recovered_count} files were successfully recovered and integrated into the reports.")
        if permanently_failed:
            print(f"🚨 Detected {len(permanently_failed)} permanent errors that could not be recovered:")
            for error in permanently_failed:
                print(f"  - File: {error['file']} (from Prompt {error['prompt_num']})\n    Reason: {error['reason']}")
        elif recovered_count > 0:
            # This case triggers if there were initial errors, but all were successfully recovered.
            print("✅ All initially failed files have been successfully recovered.")

    print("-" * 60)


# ==================================================================================================
# SCRIPT ENTRY POINT
# This block ensures the code runs only when the script is executed directly.
# ==================================================================================================
if __name__ == "__main__":
    # First, run the dependency check to ensure the environment is set up correctly.
    check_dependencies()
    # If the check passes, proceed to the main logic of the script.
    main()
