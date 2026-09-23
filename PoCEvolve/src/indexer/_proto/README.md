# scip.proto & Generated Code

This directory contains the protobuf schema and generated Python code for [SCIP](https://github.com/sourcegraph/scip), Source Graph's Source Code Intelligence Platform CLI format specification.

## Origin

- **Proto file**: Copied from https://github.com/sourcegraph/scip (MIT License, see upstream for details)
- **Generated code**: `scip_pb2.py` compiled via `grpcio-tools.protoc` from the proto definition above

## Reproducing the generated code

```bash
pip install grpcio-tools protobuf
python -m grpc_tools.protoc -I. --python_out=. scip.proto
```

## Why keep a local copy?

SCIP is an evolving format; pinning to this specific version of `scip.proto` ensures reproducible builds and eliminates runtime network dependency during compilation or code analysis.

---

**License note**: The `.proto` file is licensed under MIT by Source Graph, Inc. The generated Python file inherits the same license terms.
