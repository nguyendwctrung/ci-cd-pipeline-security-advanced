from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError


class MongoRunRepository:
    def __init__(self, uri: str, database: str, retention_days: int = 90) -> None:
        self.client = MongoClient(uri)
        self.db = self.client[database]
        self.runs = self.db.security_runs
        self.findings = self.db.security_findings
        self.signatures = self.db.ingestion_signatures
        self.retention_days = retention_days
        self.runs.create_index("run_id", unique=True)
        self.runs.create_index("run_started_at", expireAfterSeconds=retention_days * 86400)
        self.runs.create_index([("run_started_at", DESCENDING)])
        self.findings.create_index("expires_at", expireAfterSeconds=0)
        self.findings.create_index([("run_id", ASCENDING)])
        self.findings.create_index([("run_id", ASCENDING), ("severity", ASCENDING)])
        self.findings.create_index([("run_id", ASCENDING), ("tool", ASCENDING)])
        self.findings.create_index([("run_id", ASCENDING), ("file", ASCENDING)])
        self.signatures.create_index("signature", unique=True)
        self.signatures.create_index("expires_at", expireAfterSeconds=0)

    def claim_signature(self, signature: str) -> bool:
        try:
            self.signatures.insert_one({
                "signature": signature,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            })
            return True
        except DuplicateKeyError:
            return False

    def upsert(self, report: Dict[str, Any]) -> Dict[str, Any]:
        report_data = dict(report)
        run_id = str(report_data["github"]["run_id"])
        findings = report_data.pop("findings", [])
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=self.retention_days)
        document = {**report_data, "run_id": run_id, "updated_at": now}
        saved = self.runs.find_one_and_update(
            {"run_id": run_id},
            {"$set": document, "$setOnInsert": {"created_at": datetime.now(timezone.utc)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
            projection={"_id": False},
        )
        self.findings.delete_many({"run_id": run_id})
        if findings:
            self.findings.insert_many([
                {**finding, "run_id": run_id, "commit": report_data.get("git", {}).get("commit_sha", "unknown"), "expires_at": expires_at}
                for finding in findings
            ])
        return saved

    def list_runs(
        self,
        page: int,
        limit: int,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> tuple[list[Dict[str, Any]], int]:
        query: Dict[str, Any] = {}
        if status:
            query["pipeline_status"] = status
        if search:
            query["$or"] = [
                {"git.commit_sha": {"$regex": search, "$options": "i"}},
                {"github.ref": {"$regex": search, "$options": "i"}},
                {"github.repository": {"$regex": search, "$options": "i"}},
            ]
        total = self.runs.count_documents(query)
        items = list(
            self.runs.find(query, {"_id": False})
            .sort("run_started_at", DESCENDING)
            .skip((page - 1) * limit)
            .limit(limit)
        )
        return items, total

    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.runs.find_one({"run_id": run_id}, {"_id": False})

    def overview(self) -> Dict[str, Any]:
        latest = self.runs.find_one(sort=[("run_started_at", DESCENDING)], projection={"_id": False})
        last_success = self.runs.find_one(
            {"pipeline_status": "COMPLETED"},
            sort=[("run_started_at", DESCENDING)],
            projection={"_id": False},
        )
        counts = {key: 0 for key in ("COMPLETED", "BLOCKED", "ERROR")}
        for row in self.runs.aggregate([{"$group": {"_id": "$pipeline_status", "count": {"$sum": 1}}}]):
            counts[row["_id"]] = row["count"]
        return {"latest": latest, "last_success": last_success, "status_counts": counts}

    def trends(self, days: int) -> list[Dict[str, Any]]:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        pipeline = [
            {"$match": {"run_started_at": {"$gte": since}}},
            {"$sort": {"run_started_at": ASCENDING}},
            {"$project": {"_id": False}},
        ]
        return list(self.runs.aggregate(pipeline))
