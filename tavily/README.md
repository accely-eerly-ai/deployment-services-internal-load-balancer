# FastAPI Tavily Proxy

This project provides a **FastAPI Tavily Proxy** to route requests to multiple Tavily API instances with **round-robin load balancing**, **API key validation**, and **retry logic**.

---

## 📌 Features
- **Round-robin rotation** across multiple Tavily endpoints.
- **Retry policy** for transient errors (429, 500, 502, 503, 504, 401, 403, 404).
- **Client API key validation** with optional allowlist.
- **IP blocking** after repeated invalid key attempts.
- **Request ID tracking** for easier debugging.
- **Streaming responses** for efficient proxying.
- **Configurable via JSON file + environment variables**.
---
## ⚙️ Configuration

The proxy uses a JSON config file (`tavily_instances.json` by default, or via `TAVILY_PROXY_CONFIG` env var).

### Example
```json
{
  "instances": [
    { "endpoint": "https://api.tavily.com", "api_key": "Demo123" }
  ],
  "header_name": "authorization",
  "client_header_name": "authorization",
  "client_keys": ["my-key-1", "my-key-2"]
}

```

### Fields
- **instances**: List of Tavily API endpoints + API keys.
- **header_name**: Header to use when sending to Tavily (default: authorization).
- **client_header_name**: Header to check from inbound clients (default: authorization).
- **client_keys**: Optional allowlist of valid client API keys.

---

## 🚀 Running the Proxy

### 1. Install dependencies
```bash
pip install fastapi uvicorn httpx
```
### 2. Run the server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
---
## 🔐 Authentication

- Requests must include a **client API key** header (`api-key` by default).
- After `MAX_BAD_KEYS` invalid attempts (default: 5), the client IP is blocked for `BLOCK_SECONDS` (default: 300).

---

## 🔄 Load Balancing & Retry

- Round-robin rotation across configured instances.
- On failure, retries next instance in order.
- Non-retryable 4xx errors (except auth/deployment errors) return immediately.

---

## 📑 Environment Variables

| Variable                  | Default               | Description |
|---------------------------|-----------------------|-------------|
| `TAVILY_PROXY_CONFIG`      | `tavily_instances.json` | Path to JSON config |
| `ERROR_BODY_MAX_BYTES`    | `2048`                | Max bytes of error body in logs |
| `MAX_BAD_KEYS`            | `5`                   | Consecutive bad keys before block |
| `BLOCK_SECONDS`           | `300`                 | Block duration (in seconds) |

---

## 📋 Example Request

```bash
curl --location 'http://localhost:8000/search' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer my-key-1' \
--data '{
          "query": "latest news about artificial intelligence",
          "search_depth": "basic",
          "include_images": false,
          "max_results": 5
        }'
```
---

## ❌ Error Handling

- **401 Unauthorized** → Invalid or missing client API key.
- **403 Blocked** → Too many invalid attempts; IP temporarily blocked.
- **5xx / Retryable errors** → Automatically retried on other upstreams.
- **Final fallback** → Returns JSON with error details and attempt history.

---

## 📜 License

MIT License. Use at your own risk.
