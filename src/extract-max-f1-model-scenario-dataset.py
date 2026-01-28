import os
import argparse
import pandas as pd

# Possible column names for F1 and weighted F1
F1_COLS = ["F1-Score", "F1-score", "f1", "f1_score", "F1", "F1 Score"]
WEIGHTED_F1_COLS = ["Weighted F1-Score", "weighted_f1", "F1-weighted", "F1_weighted", "WeightedF1", "W-F1", "w_f1"]

DATASETS = ["Sven", "PrimeVul", "DiverseVul"]

# 🔹 DEFAULT MODEL ORDER (use here the model folder names)
MODEL_ORDER = [
    "Qwen2.5-7B-Instruct1M",
    "Qwen2.5-14B-Instruct1M",
    "Qwen2.5-32B-Instruct",
    "Qwen2.5-Coder-7B-Instruct",
    "Qwen2.5-Coder-14B-Instruct",
    "Qwen2.5-Coder-32B-Instruct",
    "CodeLlama-7B-Instruct",
    "CodeLlama-13B-Instruct",
    "CodeLlama-34B-Instruct",
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama3.1-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "DeepSeek-R1-Distill-Qwen-32B",
    "CodeAstra-7B",
    "Pongo-13B",
    "Gemini2.0-Flash",
    "Gemini2.5-Flash",
    "Gemma3-4B",
    "Gemma3-12B",
    "Gemma3-27B",
]


def estrai_metriche_da_file(xlsx_path):
    """
    Reads an Excel file and returns:
      - list of F1 values (%) found in any sheet
      - list of weighted F1 values (%) found in any sheet
    """
    try:
        all_sheets = pd.read_excel(xlsx_path, sheet_name=None)
    except Exception as e:
        print(f"    [ERROR] unable to read {xlsx_path}: {e}")
        return [], []

    f1_vals = []
    wf1_vals = []

    for _, df in all_sheets.items():
        # F1
        for col in F1_COLS:
            if col in df.columns:
                serie = pd.to_numeric(df[col], errors="coerce").dropna()
                # assume values in [0,1], convert to %
                f1_vals.extend([round(float(v) * 100, 2) for v in serie.tolist()])
                break

        # Weighted F1
        for col in WEIGHTED_F1_COLS:
            if col in df.columns:
                serie = pd.to_numeric(df[col], errors="coerce").dropna()
                wf1_vals.extend([round(float(v) * 100, 2) for v in serie.tolist()])
                break

    return f1_vals, wf1_vals


def parse_prompt_num(filename: str):
    """Extracts prompt_1/2/3 from the filename if present."""
    for p in (1, 2, 3):
        if f"prompt_{p}" in filename:
            return p
    return None


def raccogli_valori_model_dataset_scenario(model_path, dataset, scenario_idx):
    """
    Collects all F1 and W-F1 values from files:
      <model_path>/<dataset>/metrics-scenario-<scenario_idx>/*.xlsx

    Returns two lists of dicts:
      f1_entries: [{"value":..., "prompt":...}, ...]
      wf1_entries: [{"value":..., "prompt":...}, ...]
    """
    f1_entries = []
    wf1_entries = []

    scenario_folder = os.path.join(model_path, dataset, f"metrics-scenario-{scenario_idx}")
    if not os.path.isdir(scenario_folder):
        print(f"  [WARN] missing folder: {scenario_folder}")
        return f1_entries, wf1_entries

    for filename in os.listdir(scenario_folder):
        if not filename.endswith(".xlsx"):
            continue

        prompt_num = parse_prompt_num(filename)
        file_path = os.path.join(scenario_folder, filename)
        print(f"    Reading: {file_path}")

        f1_vals, wf1_vals = estrai_metriche_da_file(file_path)

        for v in f1_vals:
            f1_entries.append({"value": v, "prompt": prompt_num})

        for v in wf1_vals:
            wf1_entries.append({"value": v, "prompt": prompt_num})

    return f1_entries, wf1_entries


def max_with_prompt(entries):
    """
    entries: [{"value": float, "prompt": int|None}, ...]
    Returns: (max_val, max_prompts_str, count) or (None, None, 0)
    """
    if not entries:
        return None, None, 0

    vals = [e["value"] for e in entries]
    max_val = max(vals)
    count = len(vals)

    max_prompts = sorted(
        {str(e["prompt"]) for e in entries if e["value"] == max_val and e["prompt"] is not None}
    )
    max_prompts_str = ",".join(max_prompts) if max_prompts else None

    return max_val, max_prompts_str, count


def analyze_models(input_folder, output_path):
    if not os.path.isdir(input_folder):
        print(f"Error: input folder '{input_folder}' does not exist.")
        return

    available_models = [
        name for name in os.listdir(input_folder)
        if os.path.isdir(os.path.join(input_folder, name))
    ]

    ordered_models = []
    for m in MODEL_ORDER:
        if m in available_models:
            ordered_models.append(m)
    for m in sorted(available_models):
        if m not in ordered_models:
            ordered_models.append(m)

    # Excel writer with multiple sheets
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        summary_rows = []

        for model_name in ordered_models:
            model_path = os.path.join(input_folder, model_name)
            print(f"\n=== Model: {model_name} ===")

            rows = []
            for dataset in DATASETS:
                row = {"Dataset": dataset}

                for scenario_idx in (1, 2, 3):
                    f1_entries, wf1_entries = raccogli_valori_model_dataset_scenario(
                        model_path, dataset, scenario_idx
                    )

                    # max F1 and max W-F1 (always computed if present)
                    max_f1, max_f1_p, _ = max_with_prompt(f1_entries)
                    max_wf1, max_wf1_p, _ = max_with_prompt(wf1_entries)

                    row[f"S{scenario_idx}_max_F1(%)"] = max_f1
                    row[f"S{scenario_idx}_max_F1_prompt"] = max_f1_p
                    row[f"S{scenario_idx}_max_WF1(%)"] = max_wf1
                    row[f"S{scenario_idx}_max_WF1_prompt"] = max_wf1_p

                rows.append(row)

            df_model = pd.DataFrame(rows)

            # Write one sheet per model (sheet name ≤ 31 chars)
            sheet_name = str(model_name)[:31]
            df_model.to_excel(writer, sheet_name=sheet_name, index=False)

            # Build global summary in "long" format
            for _, r in df_model.iterrows():
                for scenario_idx in (1, 2, 3):
                    summary_rows.append({
                        "Model": model_name,
                        "Dataset": r["Dataset"],
                        "Scenario": scenario_idx,
                        "max_F1(%)": r[f"S{scenario_idx}_max_F1(%)"],
                        "max_F1_prompt": r[f"S{scenario_idx}_max_F1_prompt"],
                        "max_WF1(%)": r[f"S{scenario_idx}_max_WF1(%)"],
                        "max_WF1_prompt": r[f"S{scenario_idx}_max_WF1_prompt"],
                    })

        # Global summary sheet
        df_summary = pd.DataFrame(summary_rows)
        df_summary.to_excel(writer, sheet_name="SUMMARY", index=False)

    print(f"\n✅ Operation completed. Results saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "For each model, generates an Excel sheet with the maximum F1 and maximum W-F1 "
            "for each of the 3 scenarios and 3 datasets (Sven, PrimeVul, DiverseVul). "
            "Also generates a global SUMMARY sheet."
        ),
    )
    parser.add_argument(
        "-i", "--input-folder", required=True,
        help="Main folder containing the model subfolders."
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Path of the output Excel file."
    )

    args = parser.parse_args()
    analyze_models(args.input_folder, args.output)
