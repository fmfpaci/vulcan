import os
import pandas as pd
import argparse
from sklearn.metrics import precision_score, recall_score, accuracy_score, f1_score

# Dataset attesi sotto ogni modello
DATASETS = ["Sven", "PrimeVul", "DiverseVul"]


def is_vulnerable(value: str) -> int:
    """
    Converts a column value into a binary label.
    Returns 0 if the value is 'NOT VULNERABLE', 1 otherwise.
    """
    return 0 if str(value).strip().upper() == "NOT VULNERABLE" else 1


def compute_binary_classification_metrics(true_labels: pd.Series,
                                          predicted_labels: pd.Series) -> dict:
    """
    Calculates a complete set of binary classification metrics.
    """
    TP = ((true_labels == 1) & (predicted_labels == 1)).sum()
    TN = ((true_labels == 0) & (predicted_labels == 0)).sum()
    FP = ((true_labels == 0) & (predicted_labels == 1)).sum()
    FN = ((true_labels == 1) & (predicted_labels == 0)).sum()

    return {
        "True Positive": TP,
        "False Positive": FP,
        "True Negative": TN,
        "False Negative": FN,
        "Accuracy": accuracy_score(true_labels, predicted_labels),
        "Precision": precision_score(true_labels, predicted_labels, zero_division=0),
        "Recall": recall_score(true_labels, predicted_labels, zero_division=0),
        "F1-score": f1_score(true_labels, predicted_labels, zero_division=0),
    }


def process_excel_file(file_path: str, output_dir: str, model_name: str):
    """
    Processes a single Excel file: calculates metrics and saves the result.
    """
    try:
        df = pd.read_excel(file_path)

        required_cols = ["Actual CWE", "Found CWE"]
        if not all(col in df.columns for col in required_cols):
            print(f"  ⚠️  WARNING: File '{file_path}' skipped (missing required columns).")
            return

        df["True_Label"] = df["Actual CWE"].apply(is_vulnerable)
        df["Predicted_Label"] = df["Found CWE"].apply(is_vulnerable)

        binary_metrics = compute_binary_classification_metrics(
            df["True_Label"], df["Predicted_Label"]
        )

        # Estrae il numero di prompt dalla cartella genitore del file di input
        # Esempio: da ".../parser_output_prompt_5" estrae "5"
        prompt_dir_name = os.path.basename(os.path.dirname(file_path))
        prompt_number = "".join(filter(str.isdigit, prompt_dir_name))
        if not prompt_number:
            prompt_number = "X"  # Fallback se non trova un numero

        # Nome file di output: un file per prompt per modello
        output_filename = f"metrics_1_prompt_{prompt_number}_{model_name}.xlsx"
        output_path = os.path.join(output_dir, output_filename)

        pd.DataFrame([binary_metrics]).to_excel(output_path, index=False)
        print(f"  ✅ Metrics file created: '{output_filename}'")

    except Exception as e:
        print(f"  ❌ ERROR: Could not process file '{file_path}'. Details: {e}")


def main():
    """
    Main function to run the metrics analysis.

    Struttura attesa in modalità directory:

        /path/to/models_directory/
            Model_A/
                Sven/
                    parser_output_prompt_1/*.xlsx
                    parser_output_prompt_2/*.xlsx
                    parser_output_prompt_3/*.xlsx
                PrimeVul/
                    parser_output_prompt_1/*.xlsx
                    parser_output_prompt_2/*.xlsx
                    parser_output_prompt_3/*.xlsx
                DiverseVul/
                    parser_output_prompt_1/*.xlsx
                    parser_output_prompt_2/*.xlsx
                    parser_output_prompt_3/*.xlsx
            Model_B/
                ...
    """
    parser = argparse.ArgumentParser(
        description=(
            "Calculates binary classification metrics.\n"
            "Directory mode: input_path = base models directory.\n"
            "Single file mode (-f): input_path = path to a single .xlsx file "
            "under Model_X/<Dataset>/parser_output_prompt_X/"
        )
    )
    parser.add_argument(
        "input_path",
        type=str,
        help="Path to the main models directory OR (with -f) the path to a single .xlsx file.",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="store_true",
        help="Indicates that the provided path is a single file.",
    )
    args = parser.parse_args()
    path = args.input_path

    # --- SINGLE FILE MODE (activated by the -f flag) ---
    if args.file:
        if not os.path.isfile(path):
            print(f"❌ ERROR: The specified file does not exist: {path}")
            return

        print(f"--- Starting single file processing: {path} ---")

        # Path atteso: /.../Model_X/<Dataset>/parser_output_prompt_X/file.xlsx
        prompt_dir = os.path.dirname(path)             # .../parser_output_prompt_X
        dataset_dir = os.path.dirname(prompt_dir)      # .../<Dataset>
        model_dir = os.path.dirname(dataset_dir)       # .../Model_X

        # Cartella di output: sotto il dataset (Sven/PrimeVul/DiverseVul)
        output_dir = os.path.join(dataset_dir, "metrics-scenario-1")
        os.makedirs(output_dir, exist_ok=True)
        print(f"  -> Results will be saved in: {output_dir}")

        model_name = os.path.basename(model_dir)
        process_excel_file(path, output_dir, model_name)

    # --- DIRECTORY MODE (default behavior) ---
    else:
        if not os.path.isdir(path):
            print(f"❌ ERROR: The specified directory does not exist: {path}")
            return

        print(f"--- Starting scan in base directory: {path} ---")

        # Scorre i modelli: Model_A, Model_B, ...
        for model_name in sorted(os.listdir(path)):
            model_path = os.path.join(path, model_name)
            if not os.path.isdir(model_path):
                continue

            print(f"\nProcessing Model: {model_name}")

            # Per ogni dataset (Sven, PrimeVul, DiverseVul)
            for dataset_name in DATASETS:
                dataset_path = os.path.join(model_path, dataset_name)
                if not os.path.isdir(dataset_path):
                    print(f"  INFO: Dataset '{dataset_name}' not found for model '{model_name}'. Skipping.")
                    continue

                metrics_dir = os.path.join(dataset_path, "metrics-scenario-1")
                os.makedirs(metrics_dir, exist_ok=True)
                print(f"  Dataset: {dataset_name}")
                print(f"    -> Results will be saved in: {metrics_dir}")

                # Cerca ricorsivamente tutte le cartelle parser_output_prompt_X sotto il dataset
                for root, _, files in os.walk(dataset_path):
                    if os.path.basename(root).startswith("parser_output_prompt_"):
                        for file in files:
                            if file.endswith(".xlsx"):
                                file_path = os.path.join(root, file)
                                process_excel_file(file_path, metrics_dir, model_name)


if __name__ == "__main__":
    main()
