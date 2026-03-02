## SecretSentinel Detection Service

The detection service is a Python 3.12 FastAPI application that exposes HTTP endpoints for scanning source content for secrets.

### Endpoints

- `POST /scan`
  - Request: `{ "content": "string", "filename": "string" }`
  - Response: `{ "findings": [{ "line": int, "type": "string", "value": "string", "confidence": float }] }`

- `POST /scan/batch`
  - Request: `{ "files": [{ "content": "string", "filename": "string" }] }`
  - Response: `{ "files": [{ "filename": "string", "findings": [...] }] }`

The engine combines:

- Regex-based rules for many common secret formats.
- Shannon entropy scoring for generic high-entropy strings.
- Simple context analysis (tests, comments, examples) to assign confidence scores in the range `[0.0, 1.0]`.

See `app/` for implementation and `tests/` for pytest-based tests.
