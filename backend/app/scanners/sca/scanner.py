from __future__ import annotations
from pathlib import Path
from typing import Any
from .models import SCAResult
from .parsers import parse_manifest
from .advisories import find_advisories
from .sbom import generate_cyclonedx

MANIFEST_NAMES={'package.json','requirements.txt','pom.xml','go.mod','Cargo.toml','composer.json','Gemfile','pubspec.yaml','*.csproj','Package.swift','mix.exs','build.gradle','build.gradle.kts','gradle.properties','Podfile','CMakeLists.txt'}

class SCAScanner:
    name='sca'

    def scan_path(self, path: str, profile: str='standard') -> SCAResult:
        root=Path(path).expanduser().resolve()
        if not root.exists(): raise ValueError('SCA source path does not exist')
        def is_manifest(p):
            return p.name in {x for x in MANIFEST_NAMES if not x.startswith('*')} or (p.suffix=='.csproj')
        if root.is_file(): candidates=[root] if is_manifest(root) else []
        else: candidates=[p for p in root.rglob('*') if p.is_file() and is_manifest(p)]
        deps=[]; manifests=[]
        for m in candidates[:200]:
            try:
                parsed=parse_manifest(m)
                manifests.append({'path':str(m.relative_to(root if root.is_dir() else m.parent)),'type':m.name,'dependency_count':len(parsed)})
                deps.extend(parsed)
            except Exception as exc:
                manifests.append({'path':str(m),'type':m.name,'error':str(exc)})
        # Cheap source-aware reachability heuristic. This deliberately reports
        # "unknown" when evidence is insufficient rather than claiming reachability.
        if root.is_dir():
            source_text=''
            for p in list(root.rglob('*.py'))[:80]+list(root.rglob('*.js'))[:80]+list(root.rglob('*.ts'))[:80]+list(root.rglob('*.java'))[:40]:
                try: source_text += '\n'+p.read_text(encoding='utf-8',errors='ignore')[:200000]
                except Exception: pass
            for d in deps:
                marker=d.name.split('/')[-1].split(':')[-1].replace('-','_')
                d.reachable = (marker in source_text) if marker else None
        findings=[]
        for d in deps:
            for adv in find_advisories(d.name,d.ecosystem,d.version):
                sev=adv.severity
                findings.append({
                    'finding_key':f'SCA-{adv.advisory_id}',
                    'title':adv.title,
                    'severity':sev,
                    'confidence':'confirmed' if d.version!='unknown' else 'potential',
                    'category':'Software Supply Chain',
                    'endpoint':d.manifest,
                    'description':f'{d.ecosystem} dependency {d.name}@{d.version} matches advisory {adv.advisory_id}. Reachability={d.reachable}',
                    'evidence':{'package':d.name,'version':d.version,'ecosystem':d.ecosystem,'advisory':adv.advisory_id,'fixed_versions':adv.fixed_versions,'cwe':adv.cwe,'reachable':d.reachable},
                    'remediation':f'Upgrade {d.name} to {adv.fixed_versions[0]}' if adv.fixed_versions else f'Review and update {d.name}.',
                })
        sbom=generate_cyclonedx(deps,root.name if root.exists() else 'AegisX Project')
        return SCAResult(manifests=manifests,dependencies=deps,sbom=sbom,findings=findings)
