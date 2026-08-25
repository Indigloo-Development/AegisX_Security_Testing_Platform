from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import threading
import time
import httpx
from .models import Advisory

@dataclass
class LiveResult:
    source: str
    advisories: list[Advisory]
    ok: bool = True
    error: str | None = None
    cached: bool = False
    fetched_at: str | None = None


def _severity_from_score(score: float | None) -> str:
    if score is None: return 'unknown'
    if score >= 9.0: return 'critical'
    if score >= 7.0: return 'high'
    if score >= 4.0: return 'medium'
    return 'low'


def parse_nvd(data: dict[str, Any]) -> list[Advisory]:
    out=[]
    for row in data.get('vulnerabilities',[]) or []:
        cve=row.get('cve') or {}; aid=cve.get('id')
        if not aid: continue
        desc=next((x.get('value','') for x in cve.get('descriptions',[]) or [] if x.get('lang')=='en'),'')
        metrics=cve.get('metrics') or {}; cvss=None
        for key in ('cvssMetricV40','cvssMetricV31','cvssMetricV30'):
            vals=metrics.get(key) or []
            if vals:
                cvss=(vals[0].get('cvssData') or {}).get('baseScore')
                if cvss is not None: break
        cwes=[]
        for w in cve.get('weaknesses',[]) or []:
            for d in w.get('description',[]) or []:
                if d.get('value'): cwes.append(d['value'])
        refs=[r.get('url') for r in cve.get('references',[]) or [] if r.get('url')]
        out.append(Advisory(aid,desc,_severity_from_score(float(cvss) if cvss is not None else None),float(cvss) if cvss is not None else None,None,False,tuple(dict.fromkeys(cwes)),(),(),(),(),(),tuple(dict.fromkeys(refs)),cve.get('published'),cve.get('lastModified'),'nvd'))
    return out


def parse_osv(data: dict[str, Any]) -> list[Advisory]:
    out=[]
    for v in data.get('vulns',[]) or []:
        aid=v.get('id')
        if not aid: continue
        refs=[x.get('url') for x in v.get('references',[]) or [] if x.get('url')]
        db=v.get('database_specific') or {}
        out.append(Advisory(aid,v.get('summary') or v.get('details') or '',str(db.get('severity','unknown')).lower(),None,None,bool(db.get('known_exploited',False)),tuple(map(str,db.get('cwe',[]) or [])),(),(),(),(),(),tuple(dict.fromkeys(refs)),v.get('published'),v.get('modified'),'osv'))
    return out


def parse_kev(data: dict[str, Any], advisory_id: str | None = None) -> list[Advisory]:
    out=[]
    for item in data.get('vulnerabilities',[]) or []:
        aid=str(item.get('cveID',''))
        if not aid or (advisory_id and aid.upper()!=advisory_id.upper()): continue
        out.append(Advisory(aid,item.get('shortDescription',''),'high',None,None,True,(),(),(),(),(),(),(),item.get('dateAdded'),item.get('dueDate'),'cisa-kev'))
    return out

class TTLCache:
    def __init__(self, ttl_seconds: int = 3600): self.ttl=ttl_seconds; self._data={}; self._lock=threading.RLock()
    def get(self,key:str):
        with self._lock:
            row=self._data.get(key)
            if not row: return None
            value,expires=row
            if expires < time.time(): self._data.pop(key,None); return None
            return value
    def set(self,key:str,value:Any):
        with self._lock: self._data[key]=(value,time.time()+self.ttl)
    def clear(self):
        with self._lock: self._data.clear()

class NVDProvider:
    name='nvd-2.0'
    def __init__(self, base_url='https://services.nvd.nist.gov/rest/json/cves/2.0', timeout=15.0, api_key: str|None=None, cache: TTLCache|None=None): self.base_url=base_url; self.timeout=timeout; self.api_key=api_key; self.cache=cache or TTLCache()
    def search(self, advisory_id: str|None=None, keyword: str|None=None, force_refresh: bool=False) -> LiveResult:
        if not advisory_id and not keyword: return LiveResult(self.name,[],False,'advisory_id or keyword is required')
        key=f'nvd:{advisory_id or "kw:"+str(keyword).lower()}'
        if not force_refresh:
            cached=self.cache.get(key)
            if cached is not None: return LiveResult(self.name,cached,True,None,True,datetime.now(timezone.utc).isoformat())
        params={'cveId':advisory_id} if advisory_id else {'keywordSearch':keyword}
        headers={'User-Agent':'AegisX-Security-Research/1.0'}
        if self.api_key: headers['apiKey']=self.api_key
        try:
            with httpx.Client(timeout=self.timeout,headers=headers) as client:
                r=client.get(self.base_url,params=params); r.raise_for_status(); data=r.json()
            rows=parse_nvd(data); self.cache.set(key,rows)
            return LiveResult(self.name,rows,True,None,False,datetime.now(timezone.utc).isoformat())
        except (httpx.HTTPError,ValueError) as exc: return LiveResult(self.name,[],False,str(exc))

class OSVProvider:
    name='osv'
    def __init__(self, base_url='https://api.osv.dev/v1/query', timeout=15.0, cache: TTLCache|None=None): self.base_url=base_url; self.timeout=timeout; self.cache=cache or TTLCache()
    def search(self, package: str, ecosystem: str, version: str|None=None, force_refresh: bool=False) -> LiveResult:
        if not package or not ecosystem: return LiveResult(self.name,[],False,'package and ecosystem are required')
        key=f'osv:{ecosystem}:{package}:{version or ""}'
        if not force_refresh:
            cached=self.cache.get(key)
            if cached is not None: return LiveResult(self.name,cached,True,None,True,datetime.now(timezone.utc).isoformat())
        body={'package':{'name':package,'ecosystem':ecosystem}}
        if version: body['version']=version
        try:
            with httpx.Client(timeout=self.timeout,headers={'User-Agent':'AegisX-Security-Research/1.0'}) as client:
                r=client.post(self.base_url,json=body); r.raise_for_status(); data=r.json()
            rows=parse_osv(data); self.cache.set(key,rows)
            return LiveResult(self.name,rows,True,None,False,datetime.now(timezone.utc).isoformat())
        except (httpx.HTTPError,ValueError) as exc: return LiveResult(self.name,[],False,str(exc))

class KEVProvider:
    name='cisa-kev'
    def __init__(self,catalog_url='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',timeout=15.0,cache: TTLCache|None=None): self.catalog_url=catalog_url; self.timeout=timeout; self.cache=cache or TTLCache()
    def search(self, advisory_id: str, force_refresh: bool=False) -> LiveResult:
        key='kev:catalog'
        if not force_refresh:
            cached=self.cache.get(key)
            if cached is not None: return LiveResult(self.name,parse_kev(cached,advisory_id),True,None,True,datetime.now(timezone.utc).isoformat())
        try:
            with httpx.Client(timeout=self.timeout,headers={'User-Agent':'AegisX-Security-Research/1.0'}) as client:
                r=client.get(self.catalog_url); r.raise_for_status(); data=r.json()
            self.cache.set(key,data); rows=parse_kev(data,advisory_id)
            return LiveResult(self.name,rows,True,None,False,datetime.now(timezone.utc).isoformat())
        except (httpx.HTTPError,ValueError) as exc: return LiveResult(self.name,[],False,str(exc))
