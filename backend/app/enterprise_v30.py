from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import hashlib, hmac, secrets, time
from typing import Iterable

class Permission(str, Enum):
    READ = 'read'; WRITE = 'write'; SCAN = 'scan'; ADMIN = 'admin'

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

ROLE_PERMS = {
    'admin': {Permission.READ, Permission.WRITE, Permission.SCAN, Permission.ADMIN},
    'analyst': {Permission.READ, Permission.WRITE, Permission.SCAN},
    'viewer': {Permission.READ},
}


def authorize(role: str, action: Permission, resource_org_id: int, actor_org_id: int, *, resource_workspace_org_id: int | None = None) -> Decision:
    if resource_org_id != actor_org_id:
        return Decision(False, 'tenant_boundary')
    if resource_workspace_org_id is not None and resource_workspace_org_id != actor_org_id:
        return Decision(False, 'workspace_tenant_boundary')
    perms = ROLE_PERMS.get(role, {Permission.READ})
    if action not in perms:
        return Decision(False, 'role_policy')
    return Decision(True, 'allowed')


def hash_secret(secret: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex(), digest.hex()


def verify_secret(secret: str, salt_hex: str, digest_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(digest.hex(), digest_hex)

@dataclass
class QueueRecord:
    job_id: str
    organization_id: int
    priority: int
    attempts: int = 0
    state: str = 'queued'
    worker_id: str | None = None
    updated_at: float = 0.0

class DistributedQueue:
    """Provider-neutral queue facade; production adapters may use Redis/RabbitMQ/Kafka."""
    def __init__(self) -> None:
        self.jobs: dict[str, QueueRecord] = {}

    def submit(self, job_id: str, organization_id: int, priority: int = 50) -> QueueRecord:
        rec = QueueRecord(job_id, organization_id, int(priority), updated_at=time.time())
        self.jobs[job_id] = rec
        return rec

    def claim(self, worker_id: str, organization_id: int) -> QueueRecord | None:
        candidates = [r for r in self.jobs.values() if r.organization_id == organization_id and r.state == 'queued']
        if not candidates: return None
        rec = sorted(candidates, key=lambda r: (-r.priority, r.updated_at))[0]
        rec.state, rec.worker_id, rec.updated_at = 'running', worker_id, time.time()
        return rec

    def complete(self, job_id: str, success: bool = True) -> QueueRecord:
        rec = self.jobs[job_id]
        rec.state = 'completed' if success else 'failed'; rec.updated_at = time.time()
        return rec

@dataclass(frozen=True)
class Quota:
    max_concurrent_scans: int = 4
    max_targets: int = 100
    max_scheduled_scans: int = 50

class TenantQuotaManager:
    def __init__(self) -> None:
        self.active: dict[int, int] = {}
    def can_start(self, org_id: int, quota: Quota) -> bool:
        return self.active.get(org_id, 0) < quota.max_concurrent_scans
    def start(self, org_id: int) -> None:
        self.active[org_id] = self.active.get(org_id, 0) + 1
    def finish(self, org_id: int) -> None:
        self.active[org_id] = max(0, self.active.get(org_id, 0) - 1)

queue = DistributedQueue()
quotas = TenantQuotaManager()
