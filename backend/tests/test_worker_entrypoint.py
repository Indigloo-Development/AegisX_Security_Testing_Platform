from app.worker import main

def test_worker_entrypoint_imports():
    assert callable(main)
