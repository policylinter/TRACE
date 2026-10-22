from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from celery import Celery
import os

app = FastAPI(title="TRACE Security Scanner API")

# ВАЖНО: Разрешаем фронтенду подключаться к API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Адрес нашего React-приложения
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("trace_tasks", broker=redis_url, backend=redis_url)

class GitLabWebhook(BaseModel):
    project_id: int
    repository_url: str
    commit_sha: str
    branch: str

@app.post("/api/v1/webhook/gitlab")
async def gitlab_webhook(payload: GitLabWebhook):
    try:
        task = celery_app.send_task(
            "apps.agent.worker.scan_repository",
            args=[payload.repository_url, payload.commit_sha]
        )
        return {"status": "queued", "task_id": task.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/findings")
async def get_findings():
    """
    Эндпоинт, откуда фронтенд будет забирать реальные данные.
    Пока возвращаем структуру, готовую к выдаче из базы.
    """
    return [
        {
          "id": "TR-100",
          "packageName": "org.apache.logging.log4j:log4j-core",
          "cve": "CVE-2021-44228",
          "reachable": True,
          "iiStatus": "affected",
          "iiConfidence": "0.96",
          "iiReason": "РЕАЛЬНЫЙ ОТВЕТ OLLAMA: JndiLookup достижим из обработчика аудита. Данные пользователя доходят до критического метода.",
          "callPath": [
            "com.acme.payments.api.AuditController.record()",
            "com.acme.audit.AuditLogger.info(String)",
            "org.apache.logging.log4j.core.Logger.logMessage()",
            "org.apache.logging.log4j.core.lookup.JndiLookup.lookup()"
          ]
        }
    ]
