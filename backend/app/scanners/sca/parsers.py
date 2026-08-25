from __future__ import annotations
import json, re
from pathlib import Path
from .models import Dependency


def _version(v) -> str:
    v = str(v or '').strip()
    v = re.sub(r'^[~^<>=*v ]+', '', v)
    m = re.search(r'\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?', v)
    return m.group(0) if m else (v or 'unknown')


def parse_package_json(path: Path) -> list[Dependency]:
    data=json.loads(path.read_text(encoding='utf-8'))
    deps=[]
    for section,scope in (("dependencies","runtime"),("devDependencies","development"),("peerDependencies","runtime"),("optionalDependencies","runtime")):
        for name,ver in (data.get(section) or {}).items():
            deps.append(Dependency(name=name,version=_version(ver),ecosystem='npm',direct=True,scope=scope,manifest=str(path)))
    return deps


def parse_requirements(path: Path) -> list[Dependency]:
    deps=[]
    for raw in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or line.startswith(('-r','--','-e')): continue
        m=re.match(r'^([A-Za-z0-9_.-]+)\s*(?:==|===|>=|<=|~=|>|<)\s*([0-9][^;\s,#]*)',line)
        if m: deps.append(Dependency(name=m.group(1),version=_version(m.group(2)),ecosystem='PyPI',direct=True,scope='runtime',manifest=str(path)))
        elif re.match(r'^[A-Za-z0-9_.-]+$',line): deps.append(Dependency(name=line,version='unknown',ecosystem='PyPI',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_pom_xml(path: Path) -> list[Dependency]:
    import xml.etree.ElementTree as ET
    root=ET.parse(path).getroot(); ns={'m':'http://maven.apache.org/POM/4.0.0'} if root.tag.startswith('{') else {}
    find=lambda tag: root.findall(f'.//m:{tag}' if ns else f'.//{tag}',ns)
    deps=[]
    for d in find('dependency'):
        g=d.find('m:groupId',ns) if ns else d.find('groupId'); a=d.find('m:artifactId',ns) if ns else d.find('artifactId'); v=d.find('m:version',ns) if ns else d.find('version')
        if g is not None and a is not None: deps.append(Dependency(name=f'{g.text}:{a.text}',version=_version(v.text if v is not None else 'unknown'),ecosystem='Maven',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_go_mod(path: Path) -> list[Dependency]:
    deps=[]; in_block=False
    for raw in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        line=raw.strip()
        if line.startswith('require ('): in_block=True; continue
        if in_block and line==')': in_block=False; continue
        if in_block or line.startswith('require '):
            payload=line.removeprefix('require ').strip(); m=re.match(r'([^\s]+)\s+(v?\d[^\s]+)',payload)
            if m: deps.append(Dependency(name=m.group(1),version=_version(m.group(2)),ecosystem='Go',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_cargo(path: Path) -> list[Dependency]:
    try:
        import tomllib; data=tomllib.loads(path.read_text(encoding='utf-8'))
    except Exception: return []
    deps=[]
    for section,scope in (('dependencies','runtime'),('dev-dependencies','development'),('build-dependencies','build')):
        for name,val in (data.get(section) or {}).items():
            ver=val if isinstance(val,str) else (val or {}).get('version','unknown')
            deps.append(Dependency(name=name,version=_version(ver),ecosystem='Cargo',direct=True,scope=scope,manifest=str(path)))
    return deps


def parse_composer_json(path: Path) -> list[Dependency]:
    data=json.loads(path.read_text(encoding='utf-8')); deps=[]
    for section,scope in (('require','runtime'),('require-dev','development')):
        for name,ver in (data.get(section) or {}).items():
            if name=='php' or name.startswith('ext-'): continue
            deps.append(Dependency(name=name,version=_version(ver),ecosystem='Packagist',direct=True,scope=scope,manifest=str(path)))
    return deps


def parse_gemfile(path: Path) -> list[Dependency]:
    deps=[]
    for line in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        m=re.search(r'gem\s+[\'\"]([^\'\"]+)[\'\"](?:\s*,\s*[\'\"]([^\'\"]+)[\'\"])?',line)
        if m: deps.append(Dependency(name=m.group(1),version=_version(m.group(2) or 'unknown'),ecosystem='RubyGems',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_pubspec(path: Path) -> list[Dependency]:
    deps=[]; section=None
    for raw in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        if raw and not raw.startswith(' '):
            section=raw.rstrip(':').strip()
            continue
        if section in {'dependencies','dev_dependencies','dependency_overrides'}:
            m=re.match(r'^\s{2}([A-Za-z0-9_\-]+):\s*(.*)$',raw)
            if m: deps.append(Dependency(name=m.group(1),version=_version(m.group(2) or 'unknown'),ecosystem='pub',direct=True,scope='development' if section=='dev_dependencies' else 'runtime',manifest=str(path)))
    return deps


def parse_csproj(path: Path) -> list[Dependency]:
    import xml.etree.ElementTree as ET
    root=ET.parse(path).getroot(); deps=[]
    for node in root.iter():
        if node.tag.endswith('PackageReference'):
            name=node.attrib.get('Include') or node.attrib.get('Update'); ver=node.attrib.get('Version')
            if name: deps.append(Dependency(name=name,version=_version(ver or 'unknown'),ecosystem='NuGet',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_gradle(path: Path) -> list[Dependency]:
    deps=[]
    for line in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        m=re.search(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+[\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']",line)
        if m: deps.append(Dependency(name=f'{m.group(1)}:{m.group(2)}',version=_version(m.group(3)),ecosystem='Maven',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_package_swift(path: Path) -> list[Dependency]:
    deps=[]
    for line in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        m=re.search(r'(?:url:\s*)?[\"\'](https?://[^\"\']+)[\"\']',line)
        if m: deps.append(Dependency(name=m.group(1),version='unknown',ecosystem='SwiftPM',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_podfile(path: Path) -> list[Dependency]:
    deps=[]
    for line in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        m=re.search(r"pod\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?",line)
        if m: deps.append(Dependency(name=m.group(1),version=_version(m.group(2) or 'unknown'),ecosystem='CocoaPods',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_mix_exs(path: Path) -> list[Dependency]:
    deps=[]
    for line in path.read_text(encoding='utf-8',errors='ignore').splitlines():
        m=re.search(r'{:([a-zA-Z0-9_]+),\s*[\"\']([^\"\']+)[\"\']',line)
        if m: deps.append(Dependency(name=m.group(1),version=_version(m.group(2)),ecosystem='Hex',direct=True,scope='runtime',manifest=str(path)))
    return deps


def parse_manifest(path: Path) -> list[Dependency]:
    name=path.name
    if name=='package.json': return parse_package_json(path)
    if name=='requirements.txt': return parse_requirements(path)
    if name=='pom.xml': return parse_pom_xml(path)
    if name=='go.mod': return parse_go_mod(path)
    if name=='Cargo.toml': return parse_cargo(path)
    if name=='composer.json': return parse_composer_json(path)
    if name=='Gemfile': return parse_gemfile(path)
    if name=='pubspec.yaml': return parse_pubspec(path)
    if path.suffix=='.csproj': return parse_csproj(path)
    if name in {'build.gradle','build.gradle.kts'}: return parse_gradle(path)
    if name=='Package.swift': return parse_package_swift(path)
    if name=='Podfile': return parse_podfile(path)
    if name=='mix.exs': return parse_mix_exs(path)
    return []
