PYTHON = python3
MAIN = kry.py
KEYGEN = rsa_keygen.py
VENV = venv
ACTIVATE = . $(VENV)/bin/activate


$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)

build: $(VENV)/bin/activate
	$(ACTIVATE) && pip install -r requirements.txt

run: $(VENV)/bin/activate 
	$(ACTIVATE) && $(PYTHON) $(MAIN) $(TYPE) $(PORT)

clean:
	rm -rf $(VENV)

key_gen:
	$(ACTIVATE) && $(PYTHON) $(KEYGEN)

test:
	make run TYPE=c PORT=54321