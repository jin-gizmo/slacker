# Makefile to build doco.

dist=../dist

export PYTHONPATH=..

USER_GUIDE=slacker-user-guide

FORMATS=md site

MARKDOWN_SRC=$(shell find user-guide -name '*.md')
IMAGES=$(sort $(wildcard img/*.png) $(wildcard img/*.jpg) $(wildcard img/*.svg))
GIT_BRANCH:=$(shell git branch --show-current)

DOCS=$(patsubst %,$(dist)/doc/$(USER_GUIDE).%,$(FORMATS))
CUSTOM_DICT=$(realpath ../.aspell-dict)

SLACKER_VERSION=$(shell python3 ../slacker/version.py)
# This gets picked up in the custom mkdocs footer template
export md_footer_rhs:=v$(SLACKER_VERSION)

SCHEMA_DIR:=../slacker/schemas
SCHEMA_FILES:=$(shell find "$(SCHEMA_DIR)" -name '*.yaml')

all:	doc

doc:	user-guide

user-guide: $(DOCS)

clean:
	$(RM) -r $(dist)/doc

# Markdown as a single file.
$(dist)/doc/$(USER_GUIDE).md: $(MARKDOWN_SRC) $(IMAGES)
	@echo Generating $@
	@mkdir -p $(dist)/doc
	@find user-guide -name '*.md' -print0 | sort -z | xargs -0 -n1 sed -e '1s/^/\n/' > $@
	@cp -R img $(dist)/doc

# Generate prepared source area for published docs
%.site: %.md $(shell find mkdocs) $(SCHEMA_FILES)
	@echo Generating $@
	@( \
		$(RM) -r "$@" ; \
		cp -RL mkdocs "$@" ; \
		../etc/jinja -p version="$(SLACKER_VERSION)" mkdocs/docs/index.md > "$@/docs/index.md" ; \
		../etc/md-split --config "$@/mkdocs.yml" --dir "$@/docs" $< ; \
		cp -R $(SCHEMA_DIR) "$@/docs/schemas" ; \
		find "$@/docs/schemas" -name '*.yaml' | while read -r f ; \
		do \
			../etc/schema2json < "$$f" > "$${f%.yaml}.json" ; \
		done ; \
		find "$@" -name __pycache__ | xargs $(RM) -r ; \
		$(RM) "$@/docs/schemas/__init__.py" ; \
	)

# Serve the user guide on port 8000 for local review
preview: $(dist)/doc/$(USER_GUIDE).site
	mkdocs serve -f $</mkdocs.yml --open

_publish: $(dist)/doc/$(USER_GUIDE).site
	mkdocs gh-deploy -f $</mkdocs.yml --clean

ifeq ($(GIT_BRANCH),master)
publish: _publish

else
publish:
	$(error User guide must be published from "master" not "$(GIT_BRANCH)")
endif
	
# Spell check the user guide
spell:
	@for i in $$(find user-guide -name '*.md') ; \
	do \
		echo $$i ; \
		aspell -p $(CUSTOM_DICT) check $$i ; \
	done
