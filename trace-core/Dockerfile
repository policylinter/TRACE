# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1 — build the React bundle
# ---------------------------------------------------------------------------
FROM node:20-slim AS frontend
WORKDIR /frontend
COPY trace-frontend/package.json trace-frontend/package-lock.json* ./
RUN npm ci || npm install
COPY trace-frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — runtime: TRACE API + the compiled UI on one origin
# ---------------------------------------------------------------------------
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
COPY trace-core/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY trace-core/ .
COPY --from=frontend /frontend/dist ./frontend/dist
ENV PYTHONPATH=/app
ENV TRACE_FRONTEND_DIST=/app/frontend/dist
EXPOSE 8000
CMD ["uvicorn", "trace_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
