check: ruff mypy pylint

autofix:
	ruff format .
	ruff check --fix .

ruff:
	ruff format --check .
	ruff check -q .

pylint:
	pylint .

mypy:
	mypy .
