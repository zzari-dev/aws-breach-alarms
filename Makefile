.PHONY: tools build test test-terraform lint verify-aws all

tools:          ## Download the pinned event-ruler jars
	scripts/fetch_ruler.sh

build:          ## Regenerate cloudformation/template.json from rules/
	uv run python scripts/build_cfn.py

test: tools     ## Pattern, catalog and CloudFormation tests (offline)
	uv run pytest -m "not terraform"

test-terraform: ## Plan the module offline and compare with the catalog (downloads the AWS provider)
	uv run pytest -m terraform

lint:
	terraform fmt -check -recursive .
	uv run cfn-lint cloudformation/template.json

verify-aws:     ## Cross-check fixtures with the real EventBridge API (needs AWS credentials, creates nothing)
	uv run python scripts/verify_aws.py

all: build lint test test-terraform
