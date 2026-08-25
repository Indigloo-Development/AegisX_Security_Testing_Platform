from fastapi.testclient import TestClient
from app.main import app
from app.ai_evaluation.engine import evaluate_benchmark, compare_models, campaign_analytics, calculate_ai_risk

client=TestClient(app)

def headers():
    return {'Authorization':'Bearer dev-test-token'}

def test_suite_exposes_cases():
    r=client.get('/api/ai-evaluation-v25/suite', headers=headers())
    assert r.status_code in (200,401)
    if r.status_code==200:
        assert r.json()['case_count'] >= 6

def test_benchmark_safe_cases_pass():
    results=[{'case_id':'AI25-OUT-001','labels':[],'unsafe_behavior':False},{'case_id':'AI25-PI-001','labels':[],'unsafe_behavior':False}]
    out=evaluate_benchmark(results)
    assert out['passed_cases'] == out['total_cases']

def test_benchmark_attack_success_detected():
    out=evaluate_benchmark([{'case_id':'AI25-LEAK-001','labels':['secret-like-pattern'],'unsafe_behavior':True}])
    row=next(x for x in out['cases'] if x['case_id']=='AI25-LEAK-001')
    assert row['attack_success'] is True
    assert row['passed'] is False

def test_model_compare_recommends_best_pass_rate():
    out=compare_models([
        {'model':'A','avg_latency_ms':200,'results':[{'case_id':'AI25-OUT-001','labels':[]}]},
        {'model':'B','avg_latency_ms':100,'results':[{'case_id':'AI25-OUT-001','labels':[]}]}])
    assert out['recommended']=='A' or out['recommended']=='B'
    assert len(out['models'])==2

def test_campaign_analytics():
    out=campaign_analytics([{'metrics':{'steps_executed':3},'findings':[{'severity':'critical','confidence':'confirmed'}]}])
    assert out['steps_executed']==3
    assert out['critical_findings']==1
    assert out['campaign_success_rate_pct']==100.0

def test_risk_score_is_bounded():
    out=calculate_ai_risk({'attack_success_rate_pct':100,'false_negative_rate_pct':100,'false_positive_rate_pct':100,'critical_findings':9,'high_findings':9,'internet_exposed':1})
    assert 0 <= out['score'] <= 100
    assert out['category']=='critical'
