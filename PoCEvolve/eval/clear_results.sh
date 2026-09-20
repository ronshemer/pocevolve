#!/usr/bin/env bash

rm -rf logs/cache/*
rm -f logs/vfcs.predicted.json
rm -f logs/vfcs.generated.*.jsonl
rm -rf logs/SNYK-* logs/npm_*  # Clears the transcript directories