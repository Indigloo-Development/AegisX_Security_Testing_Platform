import json
from pathlib import Path
from app.scanners.sca_v3.engine import SCAReachabilityEngine
from app.scanners.sca_v3.graph import parse_package_lock


def test_package_lock_graph_and_direct_dependency(tmp_path: Path):
    (tmp_path/'package.json').write_text(json.dumps({'dependencies':{'lodash':'4.17.20'}}))
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':{'dependencies':{'lodash':'4.17.20'}},'node_modules/lodash':{'version':'4.17.20'}}}))
    deps,edges=parse_package_lock(tmp_path/'package-lock.json')
    assert any(d['name']=='lodash' and d['direct'] for d in deps)
    assert edges


def test_sca_v3_reachability_and_intel(tmp_path: Path):
    (tmp_path/'package.json').write_text(json.dumps({'dependencies':{'lodash':'4.17.20'}}))
    (tmp_path/'app.js').write_text("import _ from 'lodash'; console.log(_.get({}, 'x'))")
    r=SCAReachabilityEngine().analyze(str(tmp_path))
    row=next(x for x in r.reachability if x['package']=='lodash')
    assert row['status']=='direct'
    assert any(x['package']=='lodash' for x in r.intelligence)


def test_sca_v3_unknown_transitive(tmp_path: Path):
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'node_modules/fake-lib':{'version':'1.0.0'}}}))
    r=SCAReachabilityEngine().analyze(str(tmp_path))
    assert any(x['status']=='unknown' for x in r.reachability)


def test_sca_v3_supply_chain_typo_indicator(tmp_path: Path):
    (tmp_path/'package.json').write_text(json.dumps({'dependencies':{'lodas':'1.0.0'}}))
    r=SCAReachabilityEngine().analyze(str(tmp_path))
    row=next(x for x in r.supply_chain if x['package']=='lodas')
    assert any(i['type']=='typosquatting-similarity' for i in row['indicators'])
