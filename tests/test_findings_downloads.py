from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import findings as findings_api
from app.db.models import Base, Finding, Review, Target, Task
from app.db.session import get_session


def test_findings_download_status_filter_and_batch_mark(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'findings.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def setup():
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add_all([
                Task(id="task-a", name="Task A", status="done"),
                Task(id="task-b", name="Task B", status="done"),
                Target(id="target-a", task_id="task-a", url="https://a.test", host="a.test", source="manual", status="done"),
                Target(id="target-b", task_id="task-b", url="https://b.test", host="b.test", source="manual", status="done"),
            ])
            session.add_all([
                Finding(id="finding-a", task_id="task-a", target_id="target-a", vuln_type="xss", title="A", severity_claimed="low", target_url="https://a.test/x"),
                Finding(id="finding-b", task_id="task-b", target_id="target-b", vuln_type="xss", title="B", severity_claimed="low", target_url="https://b.test/x"),
                Review(id="review-a", finding_id="finding-a", task_id="task-a", verdict="accepted", confidence="confirmed", user_status="pending"),
            ])
            await session.commit()

    asyncio.run(setup())

    async def override_session():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(findings_api.router)
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        before = client.get("/api/tasks/task-a/findings", params={"compact": True}).json()
        assert before["items"][0]["downloaded"] is False

        marked = client.post(
            "/api/tasks/task-a/findings/mark-downloaded",
            json={"finding_ids": ["finding-a", "finding-b"]},
        )
        assert marked.status_code == 200
        assert marked.json()["marked_ids"] == ["finding-a"]

        downloaded = client.get(
            "/api/tasks/task-a/findings",
            params={"compact": True, "download_status": "downloaded"},
        ).json()
        assert [item["id"] for item in downloaded["items"]] == ["finding-a"]

        pending = client.get(
            "/api/tasks/task-a/findings",
            params={"compact": True, "download_status": "pending"},
        ).json()
        assert pending["items"] == []

        review = client.get("/api/tasks/task-a/review-queue", params={"download_status": "downloaded"})
        assert review.status_code == 200
        assert [item["id"] for item in review.json()] == ["finding-a"]
        assert review.json()[0]["downloaded"] is True

    asyncio.run(engine.dispose())
