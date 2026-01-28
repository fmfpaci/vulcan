#!/usr/bin/env python3
"""
plot_max_wf1_debug.py — versione con figure più grandi

- Dimensione della figura dinamica (in base al numero di barre)
- Font e label più grandi
- DPI elevato e salvataggio con bbox_inches='tight'
- Opzioni CLI per controllare dimensioni/dpi/font
- Larghezza barre aumentata per rendere leggibili le etichette sopra
- Spaziatura tra barre controllata tramite posizioni personalizzate
"""

import pandas as pd
import matplotlib.pyplot as plt
import argparse
import re
import os
import sys
import numpy as np  # <-- per gestire le posizioni delle barre

# === Ordine predefinito dei modelli (puoi modificare liberamente) ===
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

# === Funzioni di supporto ===
def normalize_colname(s):
    if s is None:
        return ""
    s = str(s).strip()
    s = s.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
    s = re.sub(r'[^0-9A-Za-z]', ' ', s)
    s = re.sub(r'\s+', ' ', s).strip().lower()
    return s

MODEL_VARIANTS = {"model", "models", "modello", "modelli", "name"}
WF1_VARIANTS = {"w f1", "wf1", "w-f1", "w_f1", "weighted f1", "weightedf1", "weighted f-score"}

def find_columns(df):
    norm_to_col = {normalize_colname(c): c for c in df.columns}
    model_col = next((orig for norm, orig in norm_to_col.items() if norm in MODEL_VARIANTS), None)
    wf1_col = next((orig for norm, orig in norm_to_col.items() if norm in WF1_VARIANTS), None)
    if not model_col:
        for norm, orig in norm_to_col.items():
            if "model" in norm or "name" in norm:
                model_col = orig
                break
    if not wf1_col:
        for norm, orig in norm_to_col.items():
            if "f1" in norm or "weighted" in norm:
                wf1_col = orig
                break
    return model_col, wf1_col

def try_find_with_header_scan(input_file, sheet_name, max_header_rows=5):
    tried = []
    for header in range(0, max_header_rows):
        try:
            df = pd.read_excel(input_file, sheet_name=sheet_name, header=header, engine="openpyxl")
        except Exception as e:
            raise RuntimeError(f"Errore lettura file Excel: {e}")
        model_col, wf1_col = find_columns(df)
        tried.append((header, list(df.columns)))
        if model_col and wf1_col:
            return df, model_col, wf1_col, tried
    return None, None, None, tried

def plot_max_wf1(input_file, sheet_name, output_file, order_list=None,
                 fig_width=None, fig_height=8.0, dpi=300,
                 title_size=18, label_size=14, tick_size=12, value_size=10,
                 rotate_xticks=60, bar_width=0.9, bar_spacing=1.4):
    df, model_col, wf1_col, tried = try_find_with_header_scan(input_file, sheet_name)

    # === DEBUG: stampa sempre le colonne trovate ===
    print("\n🧾 Colonne trovate nei vari tentativi di lettura:")
    for header, cols in tried:
        print(f"Header row: {header} → {cols}")

    if df is None:
        print("\n❌ Non sono riuscito a trovare colonne compatibili con 'Model' e 'W-F1'.")
        sys.exit(1)

    print(f"\n✅ Colonne riconosciute → Model: '{model_col}' | W-F1: '{wf1_col}'")

    # Prepara dataframe
    df = df[[model_col, wf1_col]].copy()
    df.columns = ["Model", "W-F1"]

    # Pulisci e converti
    df = df.dropna(subset=["Model", "W-F1"])
    df["Model"] = df["Model"].astype(str).str.strip()
    df["W-F1"] = pd.to_numeric(df["W-F1"].astype(str).str.replace(",", "."), errors="coerce")
    df = df.dropna(subset=["W-F1"])

    if df.empty:
        print("⚠️ Nessun dato numerico valido trovato.")
        sys.exit(2)

    # Raggruppa per modello (massimo W-F1)
    df_max = df.groupby("Model", as_index=False)["W-F1"].max()

    # Ordina secondo ordine predefinito
    if order_list is None:
        order_list = MODEL_ORDER
    ordered_models = [m for m in order_list if m in df_max["Model"].values]
    remaining = sorted([m for m in df_max["Model"].values if m not in ordered_models])
    df_max["Model"] = pd.Categorical(df_max["Model"], categories=ordered_models + remaining, ordered=True)
    df_max = df_max.sort_values("Model")

    # Trova max e min
    max_idx = df_max["W-F1"].idxmax()
    min_idx = df_max["W-F1"].idxmin()
    max_model = df_max.loc[max_idx, "Model"]
    min_model = df_max.loc[min_idx, "Model"]
    max_val = df_max.loc[max_idx, "W-F1"]
    min_val = df_max.loc[min_idx, "W-F1"]

    # Colori
    colors = ["#4C72B0"] * len(df_max)
    colors[df_max.index.get_loc(max_idx)] = "#2ECC71"
    colors[df_max.index.get_loc(min_idx)] = "#E74C3C"

    # ======== IMPOSTAZIONI PER FIGURA PIÙ GRANDE ========
    n_bars = len(df_max)
    # Larghezza dinamica: tiene conto anche della spaziatura tra barre
    if fig_width is None:
        fig_width = max(14.0, 0.6 * n_bars * bar_spacing)

    plt.rcParams.update({
        "figure.dpi": dpi,
        "savefig.dpi": dpi,
        "axes.titlesize": title_size,
        "axes.labelsize": label_size,
        "xtick.labelsize": tick_size,
        "ytick.labelsize": tick_size,
    })

    # --- Posizioni personalizzate per aumentare lo spazio tra le barre ---
    x = np.arange(n_bars) * bar_spacing  # più grande bar_spacing => più spazio tra barre

    # --- Plot ---
    plt.figure(figsize=(fig_width, fig_height))
    plt.bar(x, df_max["W-F1"].values, color=colors, width=bar_width)
    plt.xticks(x, df_max["Model"].astype(str), rotation=rotate_xticks, ha="center")
    plt.ylabel("F1 Score")
    plt.title(f"F1 Score per Model - {sheet_name}")

    # Etichette valori sopra le barre (usano le posizioni x)
    for xpos, v in zip(x, df_max["W-F1"].values):
        plt.text(xpos, v + 0.8, f"{v:.2f}", ha="center", fontsize=value_size)

    # Margini verticali per dare spazio alle etichette
    plt.margins(y=0.15)
    plt.tight_layout()

    # Salvataggio "pieno"
    plt.savefig(output_file, dpi=dpi, bbox_inches="tight")
    plt.close()

    print(f"\n📊 Grafico salvato in: {output_file}")
    print(f"   🔹 Max: {max_model} ({max_val:.2f}) | 🔸 Min: {min_model} ({min_val:.2f})")
    print(f"   📐 Figura: {fig_width:.1f}x{fig_height:.1f} inch @ {dpi} dpi (barre: {n_bars})")
    print(f"   📏 Larghezza barre: {bar_width}")
    print(f"   📏 Spaziatura tra barre (fattore): {bar_spacing}")

# === Main ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crea un barplot del Weighted F1 score per modello da un foglio Excel.")
    parser.add_argument("-i", "--input-file", required=True, help="Percorso del file Excel di input.")
    parser.add_argument("-s", "--sheet-name", required=True, help="Nome del foglio da cui leggere i dati.")
    parser.add_argument("-o", "--output-file", required=True, help="Percorso del file immagine di output (es. plot.png).")

    # ---- OPZIONI PER LA DIMENSIONE ----
    parser.add_argument("--fig-width", type=float, default=None, help="Larghezza figura in pollici (default: dinamica).")
    parser.add_argument("--fig-height", type=float, default=10.0, help="Altezza figura in pollici (default: 8.0).")
    parser.add_argument("--dpi", type=int, default=300, help="Risoluzione di salvataggio in DPI (default: 300).")
    parser.add_argument("--title-size", type=int, default=20, help="Dimensione font del titolo.")
    parser.add_argument("--label-size", type=int, default=20, help="Dimensione font degli assi.")
    parser.add_argument("--tick-size", type=int, default=20, help="Dimensione font dei tick.")
    parser.add_argument("--value-size", type=int, default=16, help="Dimensione font delle etichette sopra le barre.")
    parser.add_argument("--rotate-xticks", type=int, default=90, help="Rotazione etichette asse X.")
    parser.add_argument(
        "--bar-width",
        type=float,
        default=0.9,
        help="Larghezza delle barre (default: 0.9, più grande = più superficie per le etichette sopra)."
    )
    parser.add_argument(
        "--bar-spacing",
        type=float,
        default=1.3,
        help="Fattore di spaziatura tra le barre (default: 1.4, >1 = più spazio tra le barre)."
    )

    args = parser.parse_args()

    plot_max_wf1(
        args.input_file,
        args.sheet_name,
        args.output_file,
        fig_width=args.fig_width,
        fig_height=args.fig_height,
        dpi=args.dpi,
        title_size=args.title_size,
        label_size=args.label_size,
        tick_size=args.tick_size,
        value_size=args.value_size,
        rotate_xticks=args.rotate_xticks,
        bar_width=args.bar_width,
        bar_spacing=args.bar_spacing,
    )
