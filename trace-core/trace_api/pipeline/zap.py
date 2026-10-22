"""Bounded import of ZAP Traditional JSON reports. Never requests report URLs."""
import re
from html import unescape
from urllib.parse import urlsplit, urlunsplit


def text(value, limit=2000):
    if not isinstance(value,str):raise ValueError('Invalid ZAP text')
    return unescape(re.sub(r'<[^>]*>', '', value))[:limit]


def endpoint(value):
    if not isinstance(value,str) or len(value)>4096 or any(ord(c)<32 for c in value):raise ValueError('Invalid ZAP URL')
    parsed=urlsplit(value)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:raise ValueError('Invalid ZAP URL')
    _=parsed.port
    # Query parameters, fragments and request payloads may contain secrets.
    return urlunsplit((parsed.scheme,parsed.netloc,parsed.path or '/', '', ''))


def parse(data):
    from .ingest import RawRecord
    if not isinstance(data.get('@version'),str) or not isinstance(data.get('site'),list) or len(data['site'])>100:raise ValueError('Invalid ZAP report')
    records=[]
    for site in data['site']:
        if not isinstance(site,dict) or not isinstance(site.get('alerts'),list):raise ValueError('Invalid ZAP site')
        base=endpoint(site.get('@name'))
        for alert in site['alerts']:
            if not isinstance(alert,dict):raise ValueError('Invalid ZAP alert')
            rule=str(alert.get('alertRef') or alert.get('pluginid') or '')
            if not re.fullmatch(r'[0-9]{1,10}(?:-[0-9]{1,6})?',rule):raise ValueError('Invalid ZAP rule')
            risk=str(alert.get('riskcode'))
            if risk not in ('0','1','2','3'):raise ValueError('Invalid ZAP risk')
            title=text(alert.get('alert'),300)
            description=text(alert.get('desc',''))
            solution=text(alert.get('solution',''))
            instances=alert.get('instances')
            if not isinstance(instances,list) or not instances:raise ValueError('Missing ZAP instances')
            for instance in instances:
                if not isinstance(instance,dict):raise ValueError('Invalid ZAP instance')
                url=endpoint(instance.get('uri'))
                if urlsplit(url)[:2]!=urlsplit(base)[:2]:raise ValueError('ZAP instance outside report site')
                method=instance.get('method','GET')
                if not isinstance(method,str) or not re.fullmatch(r'[A-Z]{1,16}',method):raise ValueError('Invalid ZAP method')
                records.append(RawRecord(scanner='ZAP',cve='ZAP-'+rule,package=url,version='',ecosystem='web',severity={'0':'unknown','1':'low','2':'medium','3':'high'}[risk],cvss=0,
                    dataflow={'web':dict(url=url,method=method,ruleId=rule,title=title,description=description,solution=solution)}))
                if len(records)>5000:raise ValueError('ZAP report exceeds instance limit')
    return records
