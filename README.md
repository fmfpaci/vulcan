# Evaluating Large Language Model Capabilities for Zero-Shot Multi-Class Vulnerability Detection

## 🗂️ Repository Structure

```
vulcan/
├── datasets/                        # Folder containing the datasets to test the performance of LLMs in multi-class vulnerability detection               
├── results/                         # Folder containing the files with the outputs produced by the studied LLMs
├── src/                       # Folder containing the Python scripts used to query an LLM for multi-class vulnerability detection and to analyze their outputs
└── README.md
```
### 🔍 datasets folder

- `Sven.zip`: Sven dataset 
- `PrimeVul.zip`: PrimeVul dataset 
- `DiverseVul.zip`: DiverseVul dataset 
### 🔍 results folder
This folder includes for each studied LLMs the responses generated for all three benchmark datasets and the three zero-shot prompts.
```
results/
├── Model_A/                        # Folder containing the predictions made by Model_A per dataset and prompt        
  ├── Sven/                         # Folder containing the files with the outputs produced by the 
  ├── PrimeVul/
  ├── DiverseVul/                   # Folder containing the Python scripts used to query an LLM for multi-class vulnerability detection and to analyze their outputs
```
### 🔍 src folder
This folder includes all the Python scripts used to query the studied LLMs, process their outputs, and compute performance metrics in the three evaluation scenarios.

- `query-Google-models.py`: Python script to query Google LLMs via Google AI Studio API keys. It executes prompt1, prompt2, and prompt3 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable.
-  `quey-open-source-models.py`: Python script to query an LLM for vulnerability detection. It executes prompt1, prompt2, and prompt3 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `split-llm-output.py`: This script splits the file prompt_i_assistant_response.txt with the output produced by an LLM into different files - one file for each analyzed function
- `parser-llm-output.py`: This script has to be run after split-llm-output.py - It generates an Excel file that, for each function analyzed, reports the name of the file, the CWE identifiers of the vulnerabilities identified by an LLM, and the CWE identifiers of the vulnerabilities present
- `extract-max-f1-model-scenario-dataset.py`: P
  
