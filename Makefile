.PHONY: help setup lint compile scan clean dashboard

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:  ## Create venv and install dependencies
	python -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	@echo "Next: cp config/secrets.env.template config/secrets.env and fill in your keys"

lint:  ## Lint the pipeline with ruff
	ruff check pipeline scripts

compile:  ## Byte-compile all sources (fast syntax check)
	python -m compileall -q pipeline scripts dashboard.py reset_pipeline.py

scan:  ## Run the detect-secrets scan against the baseline
	detect-secrets scan --baseline .secrets.baseline

dashboard:  ## Launch the Streamlit analyst dashboard
	./venv/bin/streamlit run dashboard.py

clean:  ## Remove Python caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
