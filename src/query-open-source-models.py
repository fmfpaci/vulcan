import os
import glob
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

# --- Configuration ---

# CHANGE THE MODEL NAME HERE
MODEL_NAME = "meta-llama/Llama-2-7b-chat-hf"

# DIRECTORY TO ANALYZE
# Set this to the dataset folder you want to analyze
# Make sure the path is relative to the execution directory or absolute
# TEST_DIR = "../primevul/primevul-testset"
TEST_DIR = "sven"
# Absolute example: TEST_DIR = "/path/to/primevul/primevul-testset"

# --- Utility Functions ---


def load_c_files(directory_path):
    """Load the contents of .c and .cpp files from a directory."""
    filepaths = (
        glob.glob(os.path.join(directory_path, "*.c"))
        + glob.glob(os.path.join(directory_path, "*.cpp"))
        + glob.glob(os.path.join(directory_path, "*.h"))
        + glob.glob(os.path.join(directory_path, "*.cc"))
    )
    if not filepaths:
        print(f"Warning: No C or C++ files found in {directory_path}")
    for filepath in filepaths:
        try:
            # Ensure the file path being read is absolute
            full_filepath = os.path.abspath(filepath)
            with open(full_filepath, "r", encoding="utf-8") as file:
                yield os.path.basename(filepath), file.read()
        except UnicodeDecodeError:
            print(f"Skipping file {full_filepath} due to encoding error.")
        except Exception as e:
            print(f"Unexpected error while reading {full_filepath}: {e}")


# --- Main Function ---


def main():
    print(f"Loading open-source model: {MODEL_NAME}")

    # Load tokenizer and model
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float16,
        device_map="auto",
    )

    # Get the current working directory (where the script was launched)
    current_working_dir = os.getcwd()
    print(f"Script executed from: {current_working_dir}")

    # Check that TEST_DIR exists (relative or absolute)
    absolute_test_dir = os.path.abspath(TEST_DIR)
    if not os.path.isdir(absolute_test_dir):
        print(
            f"Error: Test directory not found: {absolute_test_dir} (derived from {TEST_DIR})"
        )
        return

    # --- Definition of the Relative Output Structure ---
    # Folder name for the specific model
    # Replace invalid characters in folder names
    model_folder_name = MODEL_NAME.replace("/", "_").replace("\\", "_")

    # Extract the base name of TEST_DIR as the dataset name
    normalized_test_dir = os.path.normpath(TEST_DIR)
    dataset_name = os.path.basename(normalized_test_dir)
    if not dataset_name or dataset_name == ".":
        print(
            f"Error: Could not determine a valid dataset name from TEST_DIR: {TEST_DIR}"
        )
        dataset_name = "unknown_dataset"

    # Build the output path: CWD / model_folder_name / dataset_name
    dataset_specific_output_dir = os.path.join(
        current_working_dir, model_folder_name, dataset_name
    )

    # Create the directory structure if it does not exist
    os.makedirs(dataset_specific_output_dir, exist_ok=True)

    system_prompts = [
        "If this C/C++ code snippet has vulnerabilities, output the list of corresponding CWE (Common Weakness Enumeration) identifiers; otherwise, output Not Vulnerable.",
        "You are a security researcher, expert in detecting security vulnerabilities. If this C/C++ code snippet has vulnerabilities, output the list of corresponding CWE (Common Weakness Enumeration) identifiers; otherwise, output Not Vulnerable.",
        "Analyze the provided C/C++ code for vulnerabilities. For each detected vulnerability, list the corresponding CWE (Common Weakness Enumeration) identifier. If no vulnerabilities are found, state 'Not vulnerable'.",
    ]

    for prompt_index, system_prompt in enumerate(system_prompts, 1):
        print(f"\nTesting with prompt {prompt_index}")

        output_filename_full = f"prompt_{prompt_index}_full_response.txt"
        output_filename_assistant = f"prompt_{prompt_index}_assistant_response.txt"

        txt_output_full = os.path.join(
            dataset_specific_output_dir, output_filename_full
        )
        txt_output_assistant = os.path.join(
            dataset_specific_output_dir, output_filename_assistant
        )

        # Remove existing output files if they exist
        for filepath in [txt_output_full, txt_output_assistant]:
            if os.path.exists(filepath):
                os.remove(filepath)

        for test_filename, test_code in load_c_files(absolute_test_dir):
            print(f"  Processing file: {test_filename}")

            prompt = system_prompt + "\n\n" + test_code
            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=4096,
                    temperature=0.1,
                )

            generated_text = tokenizer.decode(
                outputs[0], skip_special_tokens=True
            )

            # Save the FULL RESPONSE
            with open(txt_output_full, "a", encoding="utf-8") as f_full:
                f_full.write(f"File: {test_filename.upper()}\n")
                f_full.write(f"Full Response:\n{generated_text.upper()}\n")
                f_full.write("-" * 50 + "\n")

            # Save ONLY THE ASSISTANT RESPONSE
            with open(txt_output_assistant, "a", encoding="utf-8") as f_assist:
                f_assist.write(f"File: {test_filename.upper()}\n")
                f_assist.write(
                    f"Assistant Response:\n{generated_text.upper()}\n"
                )
                f_assist.write("-" * 50 + "\n")


if __name__ == "__main__":
    main()
