# ghidra-rpc-server make targets.
#
# We delegate the actual lint logic to tools/lint.sh (so the same script can
# be invoked from CI without going through make). Add new targets below
# following the same pattern: thin wrapper + script that does the work.

.PHONY: lint
lint:
	@./tools/lint.sh