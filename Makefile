include etc/make/help.mk

HELP_CATEGORY=Getting started

#+ What do you want to make?

# Force help category ordering
#:cat Getting started
#:cat Build targets
#:cat Install targets
#:cat User guide / documentation targets
#:cat Test targets
#:cat Miscellaneous targets

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
#:cat Getting started

## Initialise / update the project (create venv etc.). Idempotent.
init:	_venv
	git config core.hooksPath etc/git-hooks

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

# ------------------------------------------------------------------------------
#:cat Build targets

## Build the Python package
pkg:	_venv_is_on
	@mkdir -p dist/pkg
	python3 setup.py sdist --dist-dir dist/pkg

## Build the Lambda deployment package with SAM.
build:	_venv_is_on
	sam build

# ------------------------------------------------------------------------------
#:cat Install targets

## Deploy / update slacker in AWS
install: check build
	sam deploy --resolve-s3 --guided --stack-name "$(NAME)" \
		--tags "version=$(VERSION) repo-url=$(REPO)"

~/.pypirc:
	$(error You need to create $@ with an index-server section for "$(pypi)")

## Upload the pkg to the `pypi` PyPI server via twine. The `pypi` server must be
## defined in `~/.pypirc`.
#:opt pypi
pypi:	_venv_is_on ~/.pypirc pkg
	twine upload -r "$(pypi)" "dist/pkg/$(PKG)-$(VERSION).tar.gz"

# ------------------------------------------------------------------------------
#:cat User guide / documentation targets

## Make the user guide into consolidated markdown.
doc:
## Build and preview the mkdocs version of the user guide.
preview:
## Publish the user guide to GitHub pages (must be on master branch).
publish:

doc preview publish: _venv_is_on
	$(MAKE) -C doc $(MAKECMDGOALS) dist=$(abspath dist)

## Spell check the user guide (requires **aspell**).
spell:
	@for i in *.md ; \
	do \
		echo $$i ; \
		aspell -p $(CUSTOM_DICT) check $$i ; \
	done
	@$(MAKE) -C doc $(MAKECMDGOALS) dist=$(abspath dist)

# ------------------------------------------------------------------------------
#:cat Test targets

## Run the unit tests and produce a coverage report.
coverage: _venv_is_on
	@mkdir -p dist/test
	pytest --cov=. --cov-report html:dist/test/htmlcov -n "$(PYTEST_WORKERS)"

## Run the unit tests.
test:	_venv_is_on
	pytest -v -s -n "$(PYTEST_WORKERS)"

# ------------------------------------------------------------------------------
#:cat Miscellaneous targets

## Run code quality / SAM lint checks.
check:	_venv_is_on
	etc/git-hooks/pre-commit
	sam validate --lint

## Remove the ephemeral stuff.
clean:
	$(RM) -r .aws_sam dist
