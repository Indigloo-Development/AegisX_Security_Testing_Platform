from app.scaling_v33 import WorkerScalingPolicy, desired_replicas, GracefulDrain


def test_scales_up():
    p = WorkerScalingPolicy(min_replicas=2, max_replicas=10, target_queue_depth=5, scale_up_step=2)
    assert desired_replicas(20, 2, p) == 4


def test_scales_down_only_when_empty():
    p = WorkerScalingPolicy(min_replicas=2, max_replicas=10, target_queue_depth=5, scale_down_step=1)
    assert desired_replicas(0, 5, p) == 4
    assert desired_replicas(3, 5, p) == 5


def test_respects_bounds():
    p = WorkerScalingPolicy(min_replicas=2, max_replicas=3, target_queue_depth=1, scale_up_step=5)
    assert desired_replicas(100, 3, p) == 3
    assert desired_replicas(0, 2, p) == 2


def test_graceful_drain():
    d = GracefulDrain()
    assert not d.is_draining
    d.request()
    assert d.is_draining
