from app.enterprise_v30 import Permission, authorize, DistributedQueue, TenantQuotaManager, Quota, hash_secret, verify_secret

def test_tenant_boundary():
    assert authorize('analyst', Permission.READ, 1, 1).allowed
    d = authorize('analyst', Permission.READ, 2, 1)
    assert not d.allowed and d.reason == 'tenant_boundary'

def test_role_policy():
    assert authorize('viewer', Permission.READ, 1, 1).allowed
    assert not authorize('viewer', Permission.SCAN, 1, 1).allowed

def test_queue_isolation_and_priority():
    q=DistributedQueue(); q.submit('a',1,50); q.submit('b',1,90); q.submit('x',2,100)
    assert q.claim('w1',1).job_id == 'b'
    assert q.claim('w2',2).job_id == 'x'

def test_quota():
    m=TenantQuotaManager(); q=Quota(max_concurrent_scans=1)
    assert m.can_start(1,q); m.start(1); assert not m.can_start(1,q); m.finish(1); assert m.can_start(1,q)

def test_secret_hash():
    salt, digest = hash_secret('test-secret')
    assert verify_secret('test-secret',salt,digest)
    assert not verify_secret('wrong',salt,digest)
