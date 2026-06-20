#!/usr/bin/env sh

docker build . --target ghidra-server -t ghcr.io/trolldemorted/ghidra-headless-cli/ghidra-server
docker build . --target ghidra-rpc --build-context cli=../ghidra-headless-cli -t ghcr.io/trolldemorted/ghidra-headless-cli/ghidra-rpc
