import json
from pathlib import Path
from app.scanners.sca.scanner import SCAScanner
from app.scanners.sca.parsers import parse_package_json


def test_package_json_parser(tmp_path: Path):
    p=tmp_path/'package.json'
    p.write_text(json.dumps({'dependencies':{'lodash':'4.17.20','express':'4.18.3'},'devDependencies':{'vitest':'1.0.0'}}))
    deps=parse_package_json(p)
    assert {d.name for d in deps}=={'lodash','express','vitest'}


def test_sca_scan_finds_seed_advisory_and_sbom(tmp_path: Path):
    (tmp_path/'package.json').write_text(json.dumps({'dependencies':{'lodash':'4.17.20'}}))
    (tmp_path/'app.js').write_text("const lodash = require('lodash');")
    result=SCAScanner().scan_path(str(tmp_path))
    assert result.sbom['bomFormat']=='CycloneDX'
    assert len(result.dependencies)==1
    assert result.dependencies[0].reachable is True
    assert any(f['finding_key']=='SCA-AX-TEST-NPM-001' for f in result.findings)

def test_sca_additional_ecosystems(tmp_path):
    from app.scanners.sca.parsers import parse_manifest
    (tmp_path/'composer.json').write_text('{"require":{"guzzlehttp/guzzle":"^7.0"}}')
    (tmp_path/'Gemfile').write_text("gem 'rails', '~> 7.1'\n")
    (tmp_path/'x.csproj').write_text('<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>')
    (tmp_path/'build.gradle').write_text("implementation 'org.springframework:spring-core:6.1.0'\n")
    assert parse_manifest(tmp_path/'composer.json')[0].ecosystem == 'Packagist'
    assert parse_manifest(tmp_path/'Gemfile')[0].ecosystem == 'RubyGems'
    assert parse_manifest(tmp_path/'x.csproj')[0].ecosystem == 'NuGet'
    assert parse_manifest(tmp_path/'build.gradle')[0].ecosystem == 'Maven'
