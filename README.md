# LLM_Spam_Email_Detection

1. SET UP PYTHON ENVIRONMENT
Create virtual environment:

python3 -m venv ../.venv

Activate it: source ../.venv/bin/activate

Install dependencies:

pip install ollama

3. INSTALL & START OLLAMA
Install Ollama: https://ollama.com

Start Ollama: ollama serve

4. DOWNLOAD MODEL

Check installed models: ollama list

ollama pull phi

5. PROJECT FILES

software/src/main.py
software/src/config.json
software/src/prompt.txt
software/src/utils/email_parser.py
software/src/ai/ollama_classifier.py

6. VERIFY DATASET

software/data/public_phishing/phishing0/

7. RUN THE PROJECT

From inside software/src:

python3 main.py

8. USING THE PROGRAM
Program will start with:

0.eml

After each email:

Press ENTER → go to next email
Type q      → quit


9. OUTPUT EXAMPLE
File: ../data/public_phishing/phishing0/0.eml

=== MODEL THINKING ===
The email appears to impersonate a brand and includes suspicious URLs...
======================

=== CONSTRAINED OUTPUT ===
Label      : phishing
Confidence : 0.99
Decision   : Rules indicate phishing behavior...
Evidence:
  - Raw IP URL detected
  - Brand mismatch detected
----


------------------------------------

====================================
END
====================================
