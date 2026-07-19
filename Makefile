RUNTIME ?= docker
TEST_IMAGE ?= leftovers-test:local
PACKAGE_SMOKE_IMAGE ?= leftovers-package-smoke:local
SANDBOX_IMAGE ?= leftovers-sandbox:latest
REHEARSAL_IMAGE ?= leftovers-rehearsal:local
REHEARSAL_REPORT ?= .leftovers/rehearsal-report.json

.PHONY: dashboard demo guest-lock-check guest-release-preflight macos-package native-broker-check package-smoke \
	rehearsal-image sandbox-image sbx-doctor sbx-rehearsal strict-vm-check test test-local training-run \
	training-run-process validate

macos-package:
	python3 scripts/build_macos_package.py

strict-vm-check:
	sh vm/check.sh

native-broker-check:
	sh vm/broker/check.sh

sbx-doctor:
	./scripts/sbx-rehearsal.sh

sbx-rehearsal:
	./scripts/sbx-rehearsal.sh --execute

guest-lock-check:
	sh vm/guest/check-static.sh

# Intentionally fails until a reviewed builder image, public-key trust root,
# signer identities, reproducibility epoch, and provenance verifier are pinned.
guest-release-preflight:
	python3 vm/guest/release.py release-readiness

test:
	$(RUNTIME) build --tag $(TEST_IMAGE) .
	$(RUNTIME) run --rm --network none $(TEST_IMAGE)

test-local:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

package-smoke:
	$(RUNTIME) build --target package-smoke --tag $(PACKAGE_SMOKE_IMAGE) .
	$(RUNTIME) run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges=true $(PACKAGE_SMOKE_IMAGE)

sandbox-image:
	$(RUNTIME) build --file sandbox/Dockerfile --tag $(SANDBOX_IMAGE) .

rehearsal-image: sandbox-image
	$(RUNTIME) build --file sandbox/Rehearsal.Dockerfile \
		--build-arg BASE_IMAGE=$(SANDBOX_IMAGE) --tag $(REHEARSAL_IMAGE) .

training-run: rehearsal-image
	PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml \
		training-run --mode $(RUNTIME) --image $(REHEARSAL_IMAGE) \
		--profile auto --report $(REHEARSAL_REPORT)

training-run-process:
	PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml \
		training-run --mode process --profile auto --report $(REHEARSAL_REPORT)

dashboard:
	PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml \
		dashboard --host 127.0.0.1 --port 8765 --workers 4

validate:
	PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml validate

demo:
	PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml scout --fixture examples/issues.json
