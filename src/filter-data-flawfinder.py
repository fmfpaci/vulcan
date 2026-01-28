import pandas as pd
import os
import re

def leggi_file(percorso_file):
    """
    Legge file CSV o XLSX con gestione robusta dell'encoding.
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
            print("ERRORE: installa 'openpyxl' con 'pip install openpyxl' per leggere file XLSX.")
            return None
    return None


def filtra_e_sovrascrivi_excel_multi_base(cwe_config, estensione='xlsx'):
    """
    Scansiona tutte le sottocartelle di 'LLMS-Flawfinder/',
    filtra i file Excel o CSV mantenendo solo le righe che contengono
    una delle CWE specificate o 'NOT_VULNERABLE',
    e sovrascrive i file originali con la versione filtrata.
    """

    RADICE_LLMS = "/Users/federicapaci/Documents/FSE2026/ResearchQuestion4/LLMS-Flawfinder"
    cartelle_livello_3 = ['Sven', 'PrimeVul', 'DiverseVul']
    NOME_COLONNA_FILTRO = 'File Name'
    TAG_NON_VULNERABILE = 'NOT_VULNERABLE'

    if not os.path.isdir(RADICE_LLMS):
        print(f"❌ ERRORE: La cartella radice '{RADICE_LLMS}' non esiste.")
        return

    print("=" * 90)
    print("⚙️  AVVIO ELABORAZIONE FILTRAGGIO CON SOVRASCRITTURA FILE ORIGINALI")
    print(f"📂 Cartella radice: {RADICE_LLMS}")
    print(f"📄 Estensione analizzata: .{estensione}")
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
                print(f"⚠️ Nessuna CWE configurata per '{cartella_3}'. Verrà filtrato solo '{TAG_NON_VULNERABILE}'.")
                continue

            # Costruzione pattern CWE (es. 190|22|78)
            cwe_nums = '|'.join(
                re.sub(r'^0+', '', re.search(r'(\d+)', c).group(1))
                for c in cwe_da_includere if re.search(r'(\d+)', c)
            )

            # Regex robusta: riconosce CWE-190, CWE_190, CWE190, CWE-0190
            regex_pattern = (
                rf'(?<![A-Za-z0-9])CWE[-_]?0*(?:{cwe_nums})(?![A-Za-z0-9])'
                rf'|(?<![A-Za-z0-9])NOT[-_]?VULNERABLE(?![A-Za-z0-9])'
            )
            regex_compiled = re.compile(regex_pattern, re.IGNORECASE)

            print(f"\n   ▶ Modulo: {cartella_3}")
            print(f"     Pattern regex: {regex_pattern}")

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
                            print(f"        ⚠️ Colonna '{NOME_COLONNA_FILTRO}' mancante o file illeggibile: {nome_file}")
                            continue

                        col = df[NOME_COLONNA_FILTRO].astype(str)
                        mask_matches = col.apply(lambda s: bool(regex_compiled.search(str(s))))
                        matches = mask_matches.sum()
                        total_rows = len(col)
                        removed = total_rows - matches

                        if removed == 0:
                            print(f"        ✅ Nessuna riga da rimuovere in {nome_file}. File lasciato invariato.")
                            continue

                        df_filtrato = df[mask_matches].copy()

                        if len(df_filtrato) == 0:
                            print(f"        ⚠️ Nessuna riga corrispondente trovata in {nome_file}. File saltato.")
                            continue

                        # Sovrascrive il file originale
                        if estensione == 'csv':
                            df_filtrato.to_csv(percorso_file, index=False)
                        else:
                            df_filtrato.to_excel(percorso_file, index=False)

                        total_files_updated += 1
                        print(f"        💾 File sovrascritto: {nome_file}")
                        print(f"           - Righe iniziali: {total_rows}")
                        print(f"           - Righe mantenute: {len(df_filtrato)}")
                        print(f"           - Righe eliminate: {removed}")

                    except Exception as e:
                        print(f"        ❌ Errore durante l'elaborazione di {nome_file}: {e}")

    print("\n" + "=" * 90)
    print(f"🏁 PROCESSO COMPLETATO")
    print(f"   File analizzati: {total_files_processed}")
    print(f"   File sovrascritti: {total_files_updated}")
    print("=" * 90)


# ======================================================================================
# ⚙️ CONFIGURAZIONE
# ======================================================================================

CWE_CONFIGURAZIONE = {
    'Sven':      ['CWE-190', 'CWE-22', 'CWE-78'],
    'PrimeVul':  ['CWE-119', 'CWE-120', 'CWE-134', 'CWE-190', 'CWE-20', 'CWE-22',
                  'CWE-327', 'CWE-362', 'CWE-732', 'CWE-78'],
    'DiverseVul': ['CWE-119', 'CWE-120', 'CWE-134', 'CWE-190', 'CWE-20', 'CWE-22',
                   'CWE-327', 'CWE-362', 'CWE-367', 'CWE-732', 'CWE-78']
}

ESTENSIONE_FILE = 'xlsx'


# ======================================================================================
# 🚀 ESECUZIONE
# ======================================================================================

if __name__ == "__main__":
    filtra_e_sovrascrivi_excel_multi_base(CWE_CONFIGURAZIONE, ESTENSIONE_FILE)
