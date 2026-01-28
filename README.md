# How Good Are LLMs at Zero-Shot Multi-Class Vulnerability Detection?

## 🗂️ Repository Structure

```
vulcan/
├── datasets/                        # Folder containing the datasets to test the performance of LLMs in multi-class vulnerability detection               
├── results/                         # Folder containing the files with the outputs produced by the studied LLMs
├── src/                       # Folder containing the Python scripts used to query an LLM for multi-class vulnerability detection and to analyze their outputs
└── README.md
```
### 🔍 datasets folder
This folder includes the benchmark datasets we used in our study.
- `Sven.zip`: Sven dataset 
- `PrimeVul.zip`: PrimeVul dataset 
- `DiverseVul.zip`: DiverseVul dataset 
### 🔍 results folder
This folder includes, for each studied LLM, the responses generated for all three benchmark datasets and the three zero-shot prompts.
```
results/
├── Model_A/                        # Folder containing the predictions made by Model_A per dataset and prompt        
  ├── Sven/                        # Folder containing the results of the function-level analysis performed on the Sven dataset.
    ├──prompt_1_assistant_response.txt # Results of the function-level analysis performed on the Sven dataset with prompt 1
    ├──prompt_1_full_response.txt # Full response of the function-level analysis performed on the Sven dataset with prompt 1
    ├──prompt_2_assistant_response.txt # Results of the function-level analysis performed on the Sven dataset with prompt 2
    ├──prompt_2_full_response.txt # Full response of the function-level analysis performed on the Sven dataset with prompt 2
    ├──prompt_3_assistant_response.txt # Results of the function-level analysis performed on the Sven dataset with prompt 3
    ├──prompt_3_full_response.txt  # Full response of the function-level analysis performed on the Sven dataset with prompt 3       
  ├── PrimeVul/                     # Folder containing the results of the function-level analysis performed on the PrimeVul dataset.
  ├── DiverseVul/                   # Folder containing the results of the function-level analysis performed on the DiverseVul dataset.
```
### 🔍 src folder
This folder includes all the Python scripts used to query the studied LLMs, process their outputs, compute performance metrics in the three evaluation scenarios, and detect hallucinations.

- `query-Google-models.py`: Python script to query Google LLMs via Google AI Studio API keys. It executes prompt1, prompt2, and prompt3 with the specified model and dataset. The model is specified by the MODEL_NAME variable, and the dataset by the TEST_DIR variable.
-  `quey-open-source-models.py`: Python script to query an LLM for vulnerability detection. It executes prompt1, prompt2, and prompt3 with the specified model and dataset. The model is specified by the MODEL_NAME variable, and the dataset by the TEST_DIR variable. 
- `split-llm-output.py`: This script splits the file prompt_i_assistant_response.txt with the output produced by an LLM into different files - one file for each analyzed function.
- `parser-llm-output.py`: This script has to be run after split-llm-output.py - It generates an Excel file that, for each function analyzed, reports the name of the file, the CWE identifiers of the vulnerabilities identified by an LLM, and the CWE identifiers of the vulnerabilities present.
- `metrics-scenario1.py`: This script calculates for each studied LLM performance metrics precision, recall, and F1-score in evaluation scenario 1 (binary vulnerability detection).
- `metrics-scenario2.py`: This script calculates performance metrics, weighted F1-score, weighted false positive rate (FPR), and weighted false negative rate (FPN) scenario 2 (multi-class vulnerability detection).
-  `metrics-scenario3.py`: This script calculates performance metrics, weighted F1-score, weighted false positive rate (FPR), and weighted false negative rate (FNR) scenario 3 (multi-class vulnerability detection). This scenario evaluates whether the weakness predicted by an LLM is an exact match
of the weakness associated with the function or with one of its immediate parents or children in
the MITRE CWE hierarchy.
- `extract-max-f1-model-scenario-dataset.py`: This script scans experiment result folders, extracts F1 and Weighted F1 scores from Excel files for multiple models, datasets, and scenarios, and saves the maximum values into a consolidated Excel report with per-model sheets and a global summary.
- `extract-max-f1-score-per-cwe.py`: This script aggregates experimental results from multiple Excel files to compute, for each model and CWE (MITRE Top 25), the maximum F1-score observed across datasets. It outputs a consolidated Excel table with models as rows, CWEs as columns, and values ordered according to a predefined CWE ranking.
- `create-bar-plot-max-w-f1.py`: This script creates a bar plot that represents for each studied LLM the maximum F1 score or maximum weighted F1 score achieved in a given evaluation scenario.
- `heatmap.r `: This R script reads F1-score results from an Excel file and generates a heatmap showing the performance of the studied LLM across CWE classes.
- `filter-data-cppcheck.py `: This script scans a structured directory of Cppcheck analysis results, filters CSV or Excel files to retain only rows associated with selected CWE classes or marked as NOT_VULNERABLE, and overwrites the original files with the filtered data. The filtering is applied per dataset (Sven, PrimeVul, DiverseVul) using configurable CWE lists.
- `filter-data-flawfinder.py `: This script scans a structured directory of Flawfinder analysis results, filters CSV or Excel files to retain only rows associated with selected CWE classes or marked as NOT_VULNERABLE, and overwrites the original files with the filtered data. The filtering is applied per dataset (Sven, PrimeVul, DiverseVul) using configurable CWE lists.
- `detect-hallucinations.py`: This script computes hallucination rates for each studied LLM and  entity-error, invented CWE, instruction inconsistency, and context inconsistency hallucination categories.
- `admitted_cwe_updated.xlsx`: This Excel file includes the list of CWE identifiers applicable to C/C++ programming language, which is used to detect context inconsistency hallucinations.
- `cwec_latest.xml.xlsx`: This XML file contains the MITRE CWE taxonomy.
  
  
