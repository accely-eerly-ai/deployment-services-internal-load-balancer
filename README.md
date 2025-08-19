# External API Services — Self-Hosted Load Balancers (Monorepo)

Lightweight monorepo for self-hosted HTTP proxies/load‑balancers that forward requests to external API providers. Each provider lives in its own folder (examples: azure-openai, tavily) and implements common features like key validation, round‑robin instance selection, retries, logging, and optional Docker support.

Quick notes
- This README is a short index. See each service folder for in‑depth documentation and examples:
  - [azure-openai](./azure-openai/README.md)
  - [tavily](./tavily/README.md)
- To run a service locally:
  - pip install -r `<service>`/requirements.txt
  - uvicorn `<service>`.app.main:app --host 0.0.0.0 --port <port>
- Each service typically reads a JSON instances file and accepts environment overrides; check the service README for exact env vars and config keys.
- Docker Compose files are included per service for containerized runs.
- Tests available per service (pytest).

Contributing
- Add new provider in its own folder with the same structure (app/, utils/, tests/, Dockerfile, README.md).
- Keep provider README detailed; keep this top-level README concise.

License: see LICENSE files in each