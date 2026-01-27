# VULCAN - LLM-based vulnerability detection in Source Code

## 🗂️ Repository Structure

```
vulcan/
├── CodeLLama7/                      # Example of the folder with results of vulnerability detection performed by an LLM 
├── data-analysis/                   # Folder containing the file to analyze the performance of the LLM
├── inference/                       # Folder containing the script to query an LLM for vulnerability detection
├── datasets/                        # Folder containing the datasets to test the performance of LLMs in vulnerability detection
└── README.md
```
### 🔍 CodeLLama7 folder


### 🔍 datasets folder

- `sven.zip`: sven dataset divided into three subfolders. FullDataset contains the whole dataset, Training contains the portion of the dataset that has to be used to select similar examples to be included in few-shot prompts, and testSet is to be used for zero-shot and few-shot strategies to test the performance of the LLM in detecting vulnerabilities.
- `primevul.zip`: PrimeVul dataset divided into three subfolders. FullDataset contains the whole dataset, Training contains the portion of the dataset that has to be used to select similar examples to be included in few-shot prompts, and testSet is to be used for zero-shot and few-shot strategies to test the performance of the LLM in detecting vulnerabilities.
- `diversevul.zip`: DiverseVul dataset divided into three subfolders. FullDataset contains the whole dataset, Training contains the portion of the dataset that has to be used to select similar examples to be included in few-shot prompts, and testSet is to be used for zero-shot and few-shot strategies to test the performance of the LLM in detecting vulnerabilities.
- `diversevul-splitted`: DiverseVul's testSet divided into 7 subfolders

### 🔍 inference folder
- `codice-MODEL.py`: Python script to query an LLM for vulnerability detection. It executes prompt1, prompt2, and prompt3 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `codice-MODEL-prompt1.py`: Python script to query an LLM for vulnerability detection. It executes prompt1 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `codice-MODEL-prompt2.py`: Python script to query an LLM for vulnerability detection. It executes prompt2 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `codice-MODEL-prompt3.py`: Python script to query an LLM for vulnerability detection. It executes prompt3 with the specified model and dataset. The model used is specified by the variable MODEL_NAME, while the dataset is specified by the TEST_DIR variable. 
- `job-Models-30B.sbatch`: job to run LLMs with more than 30B parameters on HPC Leonardo
- `job-Models-less-15B.sbatch`: job to run LLMs with less than 20B parameters on HPC Leonardo
  
### 🔍 data-analysis folder

- `split-llm-output.py`: This is the first file to run - it splits the file prompt_i_assistant_response.txt with the output produced by an LLM into different files - one file for each analyzed function
- `parser-llm-output.py`: This file has to be run after split-llm-output.py - It generates an Excel file that for each function analyzed reports the name of the file, the CWE identifiers of the vulnerabilities identified by an LLM, and the CWE identifiers of the vulnerabilities present
  
