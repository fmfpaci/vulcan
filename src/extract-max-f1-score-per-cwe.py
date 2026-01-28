import pandas as pd
import argparse
import os
import matplotlib

# Use a non-interactive backend (for server/headless compatibility)
matplotlib.use("Agg")

# Fixed CWE order (MITRE Top 25)
CWE_TOP_25_ORDER = [
    "CWE-20",
    "CWE-22",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-119",
    "CWE-125",
    "CWE-190",
    "CWE-200",
    "CWE-269",
    "CWE-287",
    "CWE-306",
    "CWE-352",
    "CWE-400",
    "CWE-416",
    "CWE-434",
    "CWE-476",
    "CWE-502",
    "CWE-787",
    "CWE-798",
    "CWE-862",
    "CWE-863",
    "CWE-918",
]


def create_max_f1_table(input_files, output_file):
    """
    Creates an aggregated table containing, for each model and CWE,
    the MAXIMUM F1-score across all provided Excel files.
    Saves the result in Excel format.
    """
    all_dataframes = []
    dataset_names = []

    print("Analyzing input files...")
    for file_path in input_files:
        try:
            df = pd.read_excel(file_path, sheet_name="Best Prompt per Modello")
            if "CWE Class" not in df.columns:
                print(f"Warning: missing 'CWE Class' column in '{file_path}'. File skipped.")
                continue

            df.set_index("CWE Class", inplace=True)
            df = df.transpose()  # Models = rows, CWE = columns
            all_dataframes.append(df)

            abs_path = os.path.abspath(file_path)
            parent_dir_name = os.path.basename(os.path.dirname(abs_path))
            dataset_name = parent_dir_name.split("-")[0]
            dataset_names.append(dataset_name)

            print(f"File '{file_path}' processed successfully.")
        except Exception as e:
            print(f"Error while reading '{file_path}': {e}. File skipped.")

    if not all_dataframes:
        print("\nError: no valid files were processed. Unable to create the table.")
        return

    print("\nAggregating data from all datasets...")

    combined_df = pd.concat(all_dataframes)
    print(combined_df)

    # Compute the MAXIMUM F1 for each model (row) and CWE (column)
    max_df = combined_df.groupby(combined_df.index).max()

    # Custom model order (rows)
    MODEL_ORDER = [
        "Qwen2.5-7B-Instruct1M",
        "Qwen2.5-14B-Instruct1M",
        "Qwen2.5-32B-Instruct",
        "Qwen2.5-Coder-7B-Instruct",
        "Qwen2.5-Coder-14B-Instruct",
        "Qwen2.5-Coder-32B-Instruct",
        "CodeLlama-7B-Instruct",
        "CodeLlama-13B-Instruct",
        "CodeLlama-34B-Instruct"
        "DeepSeek-R1-Distill-Qwen-7B",
        "DeepSeek-R1-Distill-Llama3.1-8B",
        "DeepSeek-R1-Distill-Qwen-14B",
        "DeepSeek-R1-Distill-Qwen-32B",
        "CodeAstra-7B",
        "Pongo-13B",
        "Gemini2-Flash",
        "Gemini2.5-Flash",
        "Gemma3-4B",
        "Gemma3-12B",
        "Gemma3-27B"
    ]

    existing_models_in_order = [m for m in MODEL_ORDER if m in max_df.index]
    remaining_models = sorted([m for m in max_df.index if m not in existing_models_in_order])
    final_model_order = existing_models_in_order + remaining_models

    sorted_max_df = max_df.reindex(final_model_order)

    # Order columns according to the Top-25 CWE list (only those actually present)
    existing_columns = sorted_max_df.columns
    ordered_existing_columns = [cwe for cwe in CWE_TOP_25_ORDER if cwe in existing_columns]
    final_df = sorted_max_df.reindex(columns=ordered_existing_columns)

    print("Maximum F1 computation and ordering completed.")

    # --- Save the result to Excel ---
    try:
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        final_df.to_excel(output_file, sheet_name="Max F1 per Model-CWE")
        print(f"\nOperation completed. Excel file saved to: {output_file}")
    except Exception as e:
        print(f"Error while saving the Excel file: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Creates an Excel file containing the MAXIMUM F1-score per model and CWE "
            "from one or more input Excel files ('Best Prompt per Modello')."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--input-files",
        required=True,
        nargs="+",
        help="One or more paths to Excel files to process.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        required=True,
        help="Output path for the resulting Excel file (e.g., report/max_f1_summary.xlsx).",
    )

    args = parser.parse_args()
    create_max_f1_table(args.input_files, args.output_file)
