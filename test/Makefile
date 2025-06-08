
.PHONY: test coverage

# ------------------------------------------------------------------------------
help:
	@echo
	@echo "[31m--------------------------------------------------------------------------------"
	@echo " STOP: You should really be doing this from the base directory rather than here "
	@echo "--------------------------------------------------------------------------------[0m"
	@echo
	@echo What do you want to make?  Available targets are:
	@echo
	@echo "   help:         Print this help text."
	@echo "   test:         Run the unit tests."
	@echo "   coverage:     Run the unit tests and produce a coverage report."
	@echo


test:
	pytest -v -s

coverage:
	pytest --cov=.. --cov-report html:../dist/test/htmlcov
