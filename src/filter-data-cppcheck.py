import pandas as pd
import os
import re

def leggi_file(percorso_file):
    """
    Reads a CSV or XLSX file with robust handling of file encoding.
    """
    estensione = os.path.splitext(percorso_file)[1].lower()
    if estensione == '.csv':
        try:
            return pd.read_csv(percorso_file)
        except UnicodeDecodeError:
            return pd.read_csv(percorso_file, encoding='latin-1')
    elif estensione == '.xlsx':
        try:
            return pd.read_excel(percorso_file)
        except ImportError:
            print("ERROR: install 'openpyxl' with 'pip install openpyxl' to read XLSX files.")
            return None
    return None


def filtra_e_sovrascrivi_excel_multi_base(cwe_config, estensione='xlsx'):
    """
    Scans all subfolders of 'LLMS-Cppcheck/',
    filters Excel or CSV files by keeping only rows that contain
    one of the specified CWE identifiers or 'NOT_VULNERABLE',
    and overwrites the original files with the filtered version.
    """

    RADICE_LLMS = "/Users/federicapaci/Documents/FSE2026/ResearchQuestion4/LLMS-Cppcheck"
    cartelle_livello_3 = ['Sven', 'PrimeVul', 'DiverseVul']
    NOME_COLONNA_FILTRO = 'File Name'
    TAG_NON_VULNERABILE = 'NOT_VULNERABLE'

    if not os.path.isdir(RADICE_LLMS):
        print(f"❌ ERROR: Root folder '{RADICE_LLMS}' does not exist.")
        return

    print("=" * 90)
    print("⚙️  STARTING FILTERING PROCESS WITH FILE OVERWRITE")
    print(f"📂 Root folder: {RADICE_LLMS}")
    print(f"📄 File extension processed: .{estensione}")
    print("=" * 90)

    total_files_processed = 0
    total_files_updated = 0

    for nome_base_folder in os.listdir(RADICE_LLMS):
        percorso_base_completo = os.path.join(RADICE_LLMS, nome_base_folder)
        if not os.path.isdir(percorso_base_completo):
            continue

        print(f"\n📁 Base folder: {nome_base_folder}")

        for cartella_3 in cartelle_livello_3:
            percorso_cartella_3 = os.path.join(percorso_base_completo, cartella_3)
            if not os.path.isdir(percorso_cartella_3):
                continue

            cwe_da_includere = cwe_config.get(cartella_3, [])
            if not cwe_da_includere:
                print(
                    f"⚠️ No CWE configured for '{cartella_3}'. "
                    f"Only '{TAG_NON_VULNERABILE}' will be retained."
                )
                continue

            # Build CWE numeric pattern (e.g., 190|22|78)
            cwe_nums = '|'.join(
                re.sub(r'^0+', '', re.search(r'(\d+)', c).group(1))
                for c in cwe_da_includere if re.search(r'(\d+)', c)
            )

            # Robust regex: matches CWE-190, CWE_190, CWE190, CWE-0190
            regex_pattern = (
                rf'(?<![A-Za-z0-9])CWE[-_]?0*(?:{cwe_nums})(?![A-Za-z0-9])'
                rf'|(?<![A-Za-z0-9])NOT[-_]?VULNERABLE(?![A-Za-z0-9])'
            )
            regex_compiled = re.compile(regex_pattern, re.IGNORECASE)

            print(f"\n   ▶ Dataset: {cartella_3}")
            print(f"     Regex pattern: {regex_pattern}")

            for nome_cartella_4 in os.listdir(percorso_cartella_3):
                if not nome_cartella_4.startswith('parser_output_prompt_'):
                    continue

                percorso_cartella_4 = os.path.join(percorso_cartella_3, nome_cartella_4)
                if not os.path.isdir(percorso_cartella_4):
                    continue

                print(f"\n      🔹 Prompt folder: {nome_cartella_4}")

                for nome_file in os.listdir(percorso_cartella_4):
                    if not nome_file.endswith(f'.{estensione}'):
                        continue

                    percorso_file = os.path.join(percorso_cartella_4, nome_file)
                    total_files_processed += 1

                    try:
                        df = leggi_file(percorso_file)
                        if df is None or NOME_COLONNA_FILTRO not in df.columns:
                            print(
                                f"        ⚠️ Missing column '{NOME_COLONNA_FILTRO}' "
                                f"or unreadable file: {nome_file}"
                            )
                            continue

                        col = df[NOME_COLONNA_FILTRO].astype(str)
                        mask_matches = col.apply(
                            lambda s: bool(regex_compiled.search(str(s)))
                        )
                        matches = mask_matches.sum()
                        total_rows = len(col)
                        removed = total_rows - matches

                        if removed == 0:
                            print(
                                f"        ✅ No rows to remove in {nome_file}. "
                                f"File left unchanged."
                            )
                            continue

                        df_filtrato = df[mask_matches].copy()

                        if len(df_filtrato) == 0:
                            print(
                                f"        ⚠️ No matching rows found in {nome_file}. "
                                f"File skipped."
                            )
                            continue

                        # Overwrite the original file
                        if estensione == 'csv':
                            df_filtrato.to_csv(percorso_file, index=False)
                        else:
                            df_filtrato.to_excel(percorso_file, index=False)

                        total_files_updated += 1
                        print(f"        💾 File overwritten: {nome_file}")
                        print(f"           - Original rows: {total_rows}")
                        print(f"           - Rows kept: {len(df_filtrato)}")
                        print(f"           - Rows removed: {removed}")

                    except Exception as e:
                        print(f"        ❌ Error while processing {nome_file}: {e}")

    print("\n" + "=" * 90)
    print("🏁 PROCESS COMPLETED")
    print(f"   Files processed: {total_files_processed}")
    print(f"   Files overwritten: {total_files_updated}")
    print("=" * 90)


# ======================================================================================
# ⚙️ CONFIGURATION
# ======================================================================================

CWE_CONFIGURAZIONE = {
    'Sven':      ['CWE-190', 'CWE-416', 'CWE-476'],
    'PrimeVul':  ['CWE-119', 'CWE-190', 'CWE-252', 'CWE-362', 'CWE-369', 'CWE-401',
                  'CWE-415', 'CWE-416', 'CWE-476', 'CWE-665', 'CWE-672',
                  'CWE-703', 'CWE-704', 'CWE-772', 'CWE-834'],
    'DiverseVul': ['CWE-119', 'CWE-131', 'CWE-190', 'CWE-197', 'CWE-252',
                   'CWE-362', 'CWE-369', 'CWE-401', 'CWE-404', 'CWE-415',
                   'CWE-416', 'CWE-476', 'CWE-665', 'CWE-667', 'CWE-682',
                   'CWE-703', 'CWE-704', 'CWE-772', 'CWE-788', 'CWE-834']
}

ESTENSIONE_FILE = 'xlsx'


# ======================================================================================
# 🚀 EXECUTION
# ======================================================================================

if __name__ == "__main__":
    filtra_e_sovrascrivi_excel_multi_base(CWE_CONFIGURAZIONE, ESTENSIONE_FILE)
