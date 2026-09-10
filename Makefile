CC ?= cc
PYTHON ?= python3
CFLAGS ?= -O2
WARNINGS = -std=c11 -Wall -Wextra -Werror -pedantic

.PHONY: all help demo model oracle conformance gate gate-conformance evidence check cheri cheri-gate kfunc-kernel kfunc spatial-check spatial-selectivity-kernel spatial-selectivity-calibration spatial-selectivity ownership-kernel ownership-run ownership-trace-kernel ownership-trace ownership-case docs docs-serve private-docs private-docs-serve presentation

all: build/cbpf-demo

help:
	@printf '%s\n' 'Common targets:' '  docs-serve          Serve public research documentation on localhost:8767' '  docs                Rebuild public documentation' '  private-docs-serve  Serve local notes separately on localhost:8768' '  presentation        Alias for private-docs-serve' '  check               Run local model, conformance and evidence checks'

docs:
	$(PYTHON) tools/build_docs.py

docs-serve: docs
	@printf '%s\n' 'Documentation: http://127.0.0.1:8767/' 'Stop with Ctrl+C.'
	$(PYTHON) -m http.server 8767 --bind 127.0.0.1 --directory build/docs

private-docs:
	$(PYTHON) tools/build_docs.py --private

private-docs-serve presentation: private-docs
	@printf '%s\n' 'Private notes: http://127.0.0.1:8768/docs/private/README.html' 'Stop with Ctrl+C.'
	$(PYTHON) -m http.server 8768 --bind 127.0.0.1 --directory build/private-docs

build:
	mkdir -p $@

build/cbpf-demo: src/cbpf.c src/cbpf.h src/demo.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) src/cbpf.c src/demo.c $(LDFLAGS) -o $@

demo: build/cbpf-demo
	./build/cbpf-demo

model:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) theory/check_model.py --mutation-check

oracle:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) theory/check_oracle.py

build/cbpf-conformance.so: src/cbpf.c src/cbpf.h tools/conformance_bridge.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -fPIC -shared src/cbpf.c tools/conformance_bridge.c $(LDFLAGS) -o $@

conformance: build/cbpf-conformance.so
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) theory/check_conformance.py --library $<

build/cbpf-gate-demo: src/cbpf.c src/cbpf.h src/gate.c src/gate.h src/gate_demo.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) src/cbpf.c src/gate.c src/gate_demo.c $(LDFLAGS) -o $@

gate: build/cbpf-gate-demo
	./build/cbpf-gate-demo

build/cbpf-gate-conformance.so: src/cbpf.c src/cbpf.h src/gate.c src/gate.h tools/conformance_bridge.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -DCBPF_CONFORMANCE_GATE=1 -fPIC -shared src/cbpf.c src/gate.c tools/conformance_bridge.c $(LDFLAGS) -o $@

gate-conformance: build/cbpf-gate-conformance.so
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) theory/check_conformance.py --library $<

evidence:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) tools/verify_evidence.py

check: demo model oracle conformance gate gate-conformance evidence

# Two CVE-derived effect projections in the existing model/host implementations.
# No kernel, BPF, callback, or vulnerable-code execution.
ownership-case: build/cbpf-conformance.so build/cbpf-gate-conformance.so
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) theory/check_ownership_cve.py

# Optional external Morello runtime; no downloads and no kernel rebuild.
cheri:
	bash tools/run_cheri.sh

cheri-gate:
	bash tools/run_cheri.sh gate

# Optional pinned stock kernel build and offline guest; never part of check.
kfunc-kernel:
	bash tools/build_kfunc_kernel.sh

kfunc: kfunc-kernel
	bash tools/run_kfunc.sh

# Optional object-only compilation against the pinned inherited spatial tree.
spatial-check:
	bash tools/check_spatial.sh

# Optional synthetic native spatial matrix; never part of check.
spatial-selectivity-kernel:
	bash tools/build_spatial_selectivity.sh

spatial-selectivity-calibration:
	@test -n "$(CBPF_SPATIAL_SELECTIVITY_BUILD)" || \
		{ printf '%s\n' 'Set CBPF_SPATIAL_SELECTIVITY_BUILD to a retained build directory' >&2; exit 2; }
	bash tools/run_spatial_selectivity.sh "$(CBPF_SPATIAL_SELECTIVITY_BUILD)" --calibration

spatial-selectivity:
	@test -n "$(CBPF_SPATIAL_SELECTIVITY_BUILD)" || \
		{ printf '%s\n' 'Set CBPF_SPATIAL_SELECTIVITY_BUILD to a retained build directory' >&2; exit 2; }
	bash tools/run_spatial_selectivity.sh "$(CBPF_SPATIAL_SELECTIVITY_BUILD)"

# Optional bounded protected controls; invalid BPF remains load-only.
ownership-kernel:
	bash tools/build_ownership_kernel.sh

ownership-run:
	bash tools/run_ownership.sh

# Optional synthetic native ownership containment trace; never part of check.
ownership-trace-kernel:
	bash tools/build_ownership_trace.sh

ownership-trace:
	@test -n "$(CBPF_OWNERSHIP_TRACE_BUILD)" || \
		{ printf '%s\n' 'Set CBPF_OWNERSHIP_TRACE_BUILD to a retained build directory' >&2; exit 2; }
	bash tools/run_ownership_trace.sh "$(CBPF_OWNERSHIP_TRACE_BUILD)"
