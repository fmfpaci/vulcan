import os
import glob
import google.generativeai as genai
from dotenv import load_dotenv

# --- Configuration ---

# LOAD ENVIRONMENT VARIABLES FROM THE .env FILE
load_dotenv()

# CHANGE THE MODEL NAME HERE
# For Google AI Studio, we will use a model name like "gemini-1.5-pro-latest"
MODEL_NAME = "gemini-2.0-flash-001"

# DIRECTORY TO ANALYZE
# Set this to the dataset folder you want to analyze
# Make sure the path is relative to the execution directory or absolute
#TEST_DIR = "../primevul/primevul-testset"
TEST_DIR = "sven"
# Absolute example: TEST_DIR = "/path/to/primevul/primevul-testset"

# USE YOUR GOOGLE AI STUDIO API KEY
API_KEY = os.getenv("GOOGLE_API_KEY")  # Make sure GOOGLE_API_KEY is in your .env file

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
    # Configure the Google API
    if not API_KEY:
        print("Error: GOOGLE_API_KEY not found in environment variables.")
        return
    genai.configure(api_key=API_KEY)

    print(f"Using Google Gemini model: {MODEL_NAME}")

    # Get the current working directory (where the script was launched)
    current_working_dir = os.getcwd()
    print(f"Script executed from: {current_working_dir}")

    # Check that TEST_DIR exists (relative or absolute)
    absolute_test_dir = os.path.abspath(
        TEST_DIR
    )  # Get absolute path for safety
    if not os.path.isdir(absolute_test_dir):
        print(
            f"Error: Test directory not found: {absolute_test_dir} (derived from {TEST_DIR})"
        )
        return

    try:
        # Initialize the Gemini model
        model = genai.GenerativeModel(MODEL_NAME)
        print(f"Successfully loaded model: {MODEL_NAME}")
    except Exception as e:
        print(f"Error while loading the Gemini model: {e}")
        return

    # --- Definition of the Relative Output Structure ---
    # Folder name for the specific model
    # Replace invalid characters in folder names
    model_folder_name = MODEL_NAME.replace("/", "_").replace("\\", "_").replace(".", "_")

    # Extract the base name of TEST_DIR as the dataset name
    try:
        normalized_test_dir = os.path.normpath(TEST_DIR)
        dataset_name = os.path.basename(normalized_test_dir)
        if not dataset_name or dataset_name == ".":
            print(
                f"Error: Could not determine a valid dataset name from TEST_DIR: {TEST_DIR}"
            )
            dataset_name = "unknown_dataset"  # Fallback name
        print(f"Derived dataset name: {dataset_name}")

    except Exception as e:
        print(f"Error extracting dataset name from {TEST_DIR}: {e}")
        return

    # Build the output path: CWD / model_folder_name / dataset_name
    dataset_specific_output_dir = os.path.join(
        current_working_dir, model_folder_name, dataset_name
    )
    print(
        f"Final output directory for this dataset: {dataset_specific_output_dir}"
    )

    # Create the directory structure (model_folder_name and dataset_name) if it does not exist
    try:
        os.makedirs(dataset_specific_output_dir, exist_ok=True)
        print(
            f"Successfully ensured output directory exists: {dataset_specific_output_dir}"
        )
    except OSError as e:
        print(f"Error creating output directory {dataset_specific_output_dir}: {e}")
        return
    # ---------------------------------------------------------

    system_prompts = [
        "If this C/C++ code snippet has vulnerabilities, output the list of corresponding CWE (Common Weakness Enumeration) identifiers; otherwise, output Not Vulnerable.",
        "You are a security researcher, expert in detecting security vulnerabilities. If this C/C++ code snippet has vulnerabilities, output the list of corresponding CWE (Common Weakness Enumeration) identifiers; otherwise, output Not Vulnerable.",
        "Analyze the provided C/C++ code for vulnerabilities. For each detected vulnerability, list the corresponding CWE (Common Weakness Enumeration) identifier. If no vulnerabilities are found, state 'Not vulnerable'.",
    ]

    for prompt_index, system_prompt in enumerate(system_prompts, 1):
        print(f"\nTesting with prompt {prompt_index}: {system_prompt}")

        output_filename_full = f"prompt_{prompt_index}_full_response.txt"
        output_filename_assistant = f"prompt_{prompt_index}_assistant_response.txt"

        txt_output_full = os.path.join(
            dataset_specific_output_dir, output_filename_full
        )
        txt_output_assistant = os.path.join(
            dataset_specific_output_dir, output_filename_assistant
        )

        print(
            f"Full response output for this prompt will be saved to: {txt_output_full}"
        )
        print(
            f"Assistant-only response output for this prompt will be saved to: {txt_output_assistant}"
        )

        for filepath in [txt_output_full, txt_output_assistant]:
            if os.path.exists(filepath):
                print(
                    f"  Output file {filepath} already exists. Removing it before writing new results."
                )
                try:
                    os.remove(filepath)
                except OSError as e:
                    print(f"  Warning: Could not remove existing file {filepath}: {e}")

        found_files = False
        for test_filename, test_code in load_c_files(absolute_test_dir):
            found_files = True
            print(f"  Processing file: {test_filename}")

            # For Gemini, the prompt is passed directly or roles are used
            # Gemini handles messages as a list of dictionaries with 'role' and 'parts'
            messages = [
                {"role": "user", "parts": [system_prompt + "\n\n" + test_code]}
            ]

            try:
                # Generation with Gemini
                response = model.generate_content(
                    messages,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=4096,  # Corresponds to max_new_tokens
                    ),
                )

                try:
                    generated_text = response.text.strip()
                except ValueError:
                    generated_text = "API_RESPONSE_BLOCKED_OR_EMPTY"
                    print(
                        f"    Warning: The response for {test_filename} was blocked or is empty."
                    )

                # For Gemini, the response is already only the model output
                # There is no need to extract it from a full output like with Hugging Face
                assistant_response = generated_text

                # Save the FULL RESPONSE (which is the same as the assistant response for Gemini)
                with open(txt_output_full, "a", encoding="utf-8") as f_full:
                    f_full.write(f"File: {test_filename.upper()}\n")
                    f_full.write(f"Full Response:\n{generated_text.upper()}\n")
                    f_full.write("-" * 50 + "\n")

                # Save ONLY THE ASSISTANT RESPONSE
                with open(txt_output_assistant, "a", encoding="utf-8") as f_assist:
                    f_assist.write(f"File: {test_filename.upper()}\n")
                    f_assist.write(
                        f"Assistant Response:\n{assistant_response.upper()}\n"
                    )
                    f_assist.write("-" * 50 + "\n")

            except Exception as e:
                print(f"    An error occurred while processing {test_filename}: {e}")
                continue

        if not found_files:
            print(
                f"  No C or C++ files were processed for prompt {prompt_index} in directory {absolute_test_dir}."
            )


if __name__ == "__main__":
    main()
