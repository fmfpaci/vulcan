import os
import re
import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple

# ========================== CONSTANTS & REGEX =================================

# Regex to find and extract the original filename from a "File: ..." line.
FILENAME_REGEX = re.compile(r"File:\s*(.*)")

# CRITICAL: This regex defines the separator between entries in the log file.
# It looks for a line that *starts immediately* (no leading whitespace) with
# 40 or more hyphens. This strictness is essential to prevent it from
# accidentally matching indented separator-like lines within source code comments,
# which was the root cause of the main parsing issue.
ENTRY_SEPARATOR_REGEX = re.compile(r'^-{40,}\s*$', re.MULTILINE)

# This regex is used for a final cleanup step. It finds any separator-like
# line at the beginning of the *extracted response content*, in case the model
# output was truncated and included a separator.
CLEANUP_SEPARATOR_REGEX = re.compile(r'^\s*-{40,}', re.MULTILINE)

# Regex to remove characters that are invalid in Windows/Linux filenames.
INVALID_FILENAME_CHARS_REGEX = re.compile(r'[<>:"/\\|?*]')

# --- Configuration Constants ---

# The range of prompt files to look for (e.g., prompt_1, prompt_2, etc.).
PROMPT_RANGE = range(1, 4)
# Directory prefix to exclude during the recursive walk.
EXCLUDE_PREFIX = "part"
# Keywords to check in a filename to determine if a suffix is needed.
KEYWORDS_TO_CHECK = ("CWE", "NOT_VULNERABLE")
# Suffix to add to filenames that don't contain any of the keywords.
SUFFIX_IF_MISSING = "_NOT_VULNERABLE"

# A list of response tags, in order of priority.
# We will use robust, native string finding (`str.find()`) instead of a complex
# regex for this search. This is crucial to avoid "catastrophic backtracking"
# and silent failures on very large, complex entries.
TAG_PRIORITY_LIST = ["</THINK>", "[/INST]", "ASSISTANT"]


# ========================== UTILITY FUNCTIONS ==============================

def setup_arguments() -> argparse.Namespace:
    """
    Configures and parses command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Processes model response files by extracting content after specific tags.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("model_dir", type=str, help="Directory containing the model outputs.")
    return parser.parse_args()

def sanitize_filename(filename: str) -> str:
    """
    Removes invalid characters from a string to make it a safe filename.
    """
    return INVALID_FILENAME_CHARS_REGEX.sub('_', filename)


# ========================== CORE PROCESSING LOGIC ===============================

def process_response_file(
    file_path: Path,
    overwrite_status: Optional[bool]
) -> Tuple[int, int, Optional[bool]]:
    """
    Reads a single log file, splits it into entries, and saves the clean responses.

    Args:
        file_path: The Path object for the input file (e.g., prompt_1_full_response.txt).
        overwrite_status: The current decision for overwriting files:
                          - True: Overwrite all.
                          - False: Skip all existing files.
                          - None: Ask the user on the first encounter.

    Returns:
        A tuple containing (files_created, malformed_entries, new_overwrite_status).
    """
    try:
        # Read the entire file content. Using errors='ignore' provides resilience
        # against potential encoding issues in the log files.
        content = file_path.read_text(encoding='utf-8', errors='ignore').strip()
    except OSError as e:
        print(f"❌ Error reading file {file_path.name}: {e}", file=sys.stderr)
        return 0, 0, overwrite_status

    # Split the file content into entries using the strict separator regex.
    entries = ENTRY_SEPARATOR_REGEX.split(content)
    if not any(entry.strip() for entry in entries):
        return 0, 0, overwrite_status

    prompt_num = file_path.stem.split('_')[1]
    output_dir = file_path.parent / f'split_responses_prompt_{prompt_num}'
    output_dir.mkdir(parents=True, exist_ok=True)

    success_count = 0
    malformed_count = 0

    print(f"📄 Analyzing {file_path.name}...")

    for i, entry_text_raw in enumerate(entries):
        if not entry_text_raw.strip():
            continue

        # CRITICAL: Remove null bytes ('\x00'). These invisible characters can
        # prematurely terminate string operations in Python's C-based libraries
        # (including the regex engine), causing them to fail silently.
        # This is a crucial sanitization step.
        entry_text = entry_text_raw.replace('\x00', '')

        filename_match = FILENAME_REGEX.search(entry_text)

        # --- Robust Tag Finding Logic ---
        start_pos = -1
        # Create an uppercase version of the text once for efficient, case-insensitive search.
        upper_entry_text = entry_text.upper()

        # Iterate through tags in priority order.
        for tag in TAG_PRIORITY_LIST:
            # Use the highly reliable and fast str.find() method.
            found_pos = upper_entry_text.find(tag.upper())
            if found_pos != -1:
                # Tag found! Calculate the start position of the response content
                # (immediately after the tag) and stop searching.
                start_pos = found_pos + len(tag)
                break

        # --- Process the entry based on findings ---
        if filename_match and start_pos != -1:
            # HAPPY PATH: Both filename and a response tag were found.
            target_filename_raw = filename_match.group(1).strip()

            # Extract the raw response content using the calculated start position.
            response_content_raw = entry_text[start_pos:]

            # Clean up any trailing separator line that might have been part of the output.
            separator_match = CLEANUP_SEPARATOR_REGEX.search(response_content_raw)
            if separator_match:
                cleaned_content = response_content_raw[:separator_match.start()]
            else:
                cleaned_content = response_content_raw

            response_content = cleaned_content.strip()

            # Construct the final output filename.
            base_name = Path(target_filename_raw).name
            name_part, extension = Path(base_name).stem, Path(base_name).suffix

            if not any(keyword in name_part.upper() for keyword in KEYWORDS_TO_CHECK):
                name_part += SUFFIX_IF_MISSING

            safe_name = sanitize_filename(name_part + extension)
            output_path = output_dir / safe_name

            # Handle overwriting of existing files.
            if output_path.exists():
                if overwrite_status is None:
                    answer = input(f"❓ '{safe_name}' exists. Overwrite all? (y/N/q): ").lower().strip()
                    if answer.startswith('y'):
                        print("   -> OK. Overwriting all subsequent files.")
                        overwrite_status = True
                    elif answer.startswith('q'):
                        print("   -> Aborting process.")
                        sys.exit(0)
                    else:
                        print("   -> OK. Skipping all existing files.")
                        overwrite_status = False

                if not overwrite_status:
                    continue

            try:
                output_path.write_text(response_content, encoding='utf-8')
                success_count += 1
            except OSError as e:
                print(f"   - ❌ Error writing file '{safe_name}': {e}", file=sys.stderr)
        else:
            # MALFORMED PATH: Something was missing.
            malformed_count += 1
            reasons = []
            if not filename_match:
                reasons.append("missing 'File:' line")
            if start_pos == -1:
                reasons.append("no response tag found")
            
            reason_str = " and ".join(reasons).capitalize()
            entry_snippet = entry_text.strip().replace('\n', ' ')[:100] + '...'
            print(f"   - ⚠️  Skipping entry #{i+1}: {reason_str}")
            print(f"       Content: \"{entry_snippet}\"")

    print(f"✅ Finished {file_path.name} -> OK: {success_count} files created, Skipped: {malformed_count} malformed entries")
    return success_count, malformed_count, overwrite_status

# ============================= MAIN ==========================================
def main():
    """
    Main function to orchestrate the entire process.
    """
    args = setup_arguments()
    model_dir_path = Path(args.model_dir)

    if not model_dir_path.is_dir():
        print(f"❌ Error: Invalid directory specified: '{model_dir_path}'", file=sys.stderr)
        sys.exit(1)

    overwrite_all: Optional[bool] = None
    total_files_processed, total_responses_saved, total_malformed_skipped = 0, 0, 0

    print(f"🚀 Starting process in directory: {model_dir_path}")

    # First, gather all files to be processed to avoid nested printing issues.
    all_files_to_process = []
    for root, dirs, files in os.walk(model_dir_path):
        # Exclude specified directories.
        dirs[:] = [d for d in dirs if not d.lower().startswith(EXCLUDE_PREFIX)]
        for i in PROMPT_RANGE:
            target_filename = f'prompt_{i}_full_response.txt'
            if target_filename in files:
                all_files_to_process.append(Path(root) / target_filename)

    if not all_files_to_process:
        print("\n🤔 No 'prompt_*_full_response.txt' files found in the scanned directories.")
        sys.exit(0)

    # Now, process each found file.
    for file_path in all_files_to_process:
        print("-" * 60)
        success, malformed, overwrite_all = process_response_file(file_path, overwrite_all)
        total_files_processed += 1
        total_responses_saved += success
        total_malformed_skipped += malformed

    # Print the final summary.
    print("\n" + "="*60)
    print("✨ Processing complete!")
    print(f"   - Total log files analyzed: {total_files_processed}")
    print(f"   - Total responses saved: {total_responses_saved}")
    print(f"   - Total malformed entries skipped: {total_malformed_skipped}")
    print("="*60)


if __name__ == "__main__":
    main()
