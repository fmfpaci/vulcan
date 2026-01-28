# Evaluating Large Language Model Capabilities for Zero-Shot
Multi-Class Vulnerability Detection

## 🗂️ Repository Structure

```
vulcan/
├── datasets/                        # Folder containing the datasets to test the performance of LLMs in multi-class vulnerability detection               
├── results/                         # Folder containing the files with the outputs produced by thes studied LLMs
├── inference/                       # Folder containing the Python scripts used to query an LLM for multi-class vulnerability detection and to analyze their outputs
└── README.md
```
### 🔍 datasets folder

- `Sven.zip`: Sven dataset 
- `PrimeVul.zip`: PrimeVul dataset 
- `DiverseVul.zip`: DiverseVul dataset 
### 🔍 output folder

### 🔍 src folder
- `codice-MODEL.py`: Python script to query an LLM for vulnerability detection. It executes prompt1, prompt2, and prompt3 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `codice-MODEL-prompt1.py`: Python script to query an LLM for vulnerability detection. It executes prompt1 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `codice-MODEL-prompt2.py`: Python script to query an LLM for vulnerability detection. It executes prompt2 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `codice-MODEL-prompt3.py`: Python script to query an LLM for vulnerability detection. It executes prompt3 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `job-Models-30B.sbatch`: job to run LLMs with more than 30B parameters on HPC Leonardo
- `job-Models-less-15B.sbatch`: job to run LLMs with less than 20B parameters on HPC Leonardo
  
### 🔍 data-analysis folder

- `split-llm-output.py`: This is the first file to run - it splits the file prompt_i_assistant_response.txt with the output produced by an LLM into different files - one file for each analyzed function
- `parser-llm-output.py`: This file has to be run after split-llm-output.py - It generates an Excel file that for each function analyzed reports the name of the file, the CWE identifiers of the vulnerabilities identified by an LLM, and the CWE identifiers of the vulnerabilities present
  
