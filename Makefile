pypi=pypi

# ------------------------------------------------------------------------------
PYTHON3=python3.13
REPO=https://github.com/jin-gizmo/slacker
NAME=slacker
PKG=jinslacker
VERSION:=$(shell slacker/version.py)
SRC=$(shell find slacker -path 'slacker/__pycache__' -prune -false -o -type f)
PYTEST_WORKERS=2
CUSTOM_DICT=$(realpath .aspell-dict)

.PHONY: black help _venv_is_off _venv_is_on _venv update check cookie doc spell test coverage pypi


# ------------------------------------------------------------------------------
help:
	@echo
	@echo What do you want to make?  Available targets are:
	@echo
	@echo "[31mGetting started[0m"
	@echo "   init:      Initialise / update the project (create venv etc.). Idempotent."
	@echo "   help:      Print help."
	@echo
	@echo "[31mBuild targets[0m"
	@echo "   pkg:       Build the Python package."
	@echo "   build:     Build the Lambda deployment package with SAM."
	@echo
	@echo "[31mInstall targets[0m"
	@echo "   install:   Deploy / update slacker in AWS."
	@echo "   pypi:      Upload the pkg to the \"$(pypi)\" PyPI server via twine. The"
	@echo "              \"$(pypi)\" server must be defined in ~/.pypirc. Add pypi=..."
	@echo "              to specify a different index server entry in ~/.pypirc."
	@echo
	@echo "[31mUser guide / documentation targets[0m"
	@echo "   doc:       Make the user guide into consolidated markdown."
	@echo "   preview:   Build and preview the mkdocs version of the user guide."
	@echo "   publish:   Publish the user guide to GitHub pages (must be on master branch)."
	@echo "   spell:     Spell check the user guide (requires aspell)."
	@echo
	@echo "[31mMiscellaneous targets[0m"
	@echo "   check:     Run code quality / SAM lint checks."
	@echo "   clean:     Remove the ephemeral stuff."
	@echo
	@echo "[31mTesting targets[0m"
	@echo "   coverage:  Run the unit tests and produce a coverage report."
	@echo "   test:      Run the unit tests."
	@echo


# ------------------------------------------------------------------------------
# Setup targets

_venv_is_off:
	@if [ "$$VIRTUAL_ENV" != "" ] ; \
	then \
		echo Deactivate your virtualenv for this operation ; \
		exit 1 ; \
	fi

_venv_is_on:
	@if [ "$$VIRTUAL_ENV" == "" ] ; \
	then \
		echo Activate your virtualenv for this operation ; \
		exit 1 ; \
	fi
	

# Setup the virtual environment
_venv:	_venv_is_off
	@if [ ! -d venv ] ; \
	then \
		echo Creating virtualenv ; \
		$(PYTHON3) -m venv venv ; \
	fi
	@( \
		echo Activating venv ; \
		source venv/bin/activate ; \
		export PIP_INDEX_URL=$(PIP_INDEX_URL) ; \
		echo Installing requirements ; \
		$(PYTHON3) -m pip install pip --upgrade ; \
		$(PYTHON3) -m pip install -r requirements-build.txt --upgrade ; \
		$(PYTHON3) -m pip install -r slacker/requirements.txt --upgrade ; \
		$(PYTHON3) -m pip install -r requirements.txt --upgrade ; \
		: ; \
	)

init:	_venv
	git config core.hooksPath etc/git-hooks

# ------------------------------------------------------------------------------
#  Build targets

pkg:	_venv_is_on
	@mkdir -p dist/pkg
	python3 setup.py sdist --dist-dir dist/pkg

build:	_venv_is_on
	sam build
	
# ------------------------------------------------------------------------------
#  Install targets

install: check build
	sam deploy --resolve-s3 --guided --stack-name "$(NAME)" \
		--tags "version=$(VERSION) repo-url=$(REPO)"

~/.pypirc:
	$(error You need to create $@ with an index-server section for "$(pypi)")

pypi:	_venv_is_on ~/.pypirc pkg
	twine upload -r "$(pypi)" "dist/pkg/$(PKG)-$(VERSION).tar.gz"

# ------------------------------------------------------------------------------
# Documentation targets
doc preview publish:
	$(MAKE) -C doc $(MAKECMDGOALS) dist=$(abspath dist)

spell:
	@for i in *.md ; \
	do \
		echo $$i ; \
		aspell -p $(CUSTOM_DICT) check $$i ; \
	done
	@$(MAKE) -C doc $(MAKECMDGOALS) dist=$(abspath dist)

# ------------------------------------------------------------------------------
#  Test targets

coverage: _venv_is_on
	@mkdir -p dist/test
	pytest --cov=. --cov-report html:dist/test/htmlcov -n "$(PYTEST_WORKERS)"

test:	_venv_is_on
	pytest -v -s -n "$(PYTEST_WORKERS)"

# ------------------------------------------------------------------------------
#  Miscellaneous

check:	_venv_is_on
	etc/git-hooks/pre-commit
	sam validate --lint
clean:
	$(RM) -r .aws_sam dist
