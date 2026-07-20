#!/bin/bash

# vfcs.predicted.json comes from PoCEvolve folder
node index.js vfc-pipeline --vfcDataPath ./vfcs.predicted.json -m qwen/qwen3.7-plus dataset/SecBench.js.all