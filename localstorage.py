import base64
import posixpath
import re
import sqlite3
import json
import xml.etree.ElementTree as ET
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB_PATH = Path(__file__).with_suffix('.db')
STORAGE_KEY = 'mailInfraDashboardDataV4'
REMOTE_BASE_DIR = '/root'
PMTA_REMOTE_CONFIG_PATH = '/etc/pmta/config'
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$')
SELECTOR_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')


class NamecheapAPIError(Exception):
    pass


class NamecheapClient:
    PRODUCTION_URL = "https://api.namecheap.com/xml.response"
    SANDBOX_URL = "https://api.sandbox.namecheap.com/xml.response"

    def __init__(
        self,
        api_user: str,
        api_key: str,
        username: str,
        client_ip: str,
        sandbox: bool = False,
        timeout: int = 30,
    ):
        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip
        self.timeout = timeout
        self.base_url = self.SANDBOX_URL if sandbox else self.PRODUCTION_URL

    def _base_params(self, command: str) -> Dict[str, str]:
        return {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIp": self.client_ip,
            "Command": command,
        }

    def _call(self, command: str, extra_params: Optional[Dict[str, str]] = None) -> ET.Element:
        params = self._base_params(command)
        if extra_params:
            params.update(extra_params)

        encoded = urllib.parse.urlencode(params).encode("utf-8")
        request_obj = urllib.request.Request(
            self.base_url,
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request_obj, timeout=self.timeout) as response:
                response_text = response.read().decode("utf-8", errors="replace")
        except Exception as exc:
            raise NamecheapAPIError(f"Namecheap request failed: {exc}") from exc

        try:
            root = ET.fromstring(response_text)
        except ET.ParseError as exc:
            raise NamecheapAPIError(f"Invalid XML response: {exc}\nRaw response:\n{response_text}") from exc

        if root.attrib.get("Status") != "OK":
            errors = []
            for err in root.findall(".//{*}Error"):
                code = err.attrib.get("Number", "Unknown")
                errors.append(f"[{code}] {err.text}")
            if not errors:
                errors.append("Unknown API error")
            raise NamecheapAPIError(" | ".join(errors))

        return root

    @staticmethod
    def split_domain(domain: str) -> Tuple[str, str]:
        clean = (domain or "").strip().lower()
        if "." not in clean:
            raise ValueError("Invalid domain name")
        return clean.rsplit(".", 1)

    def list_domains(self, page: int = 1, page_size: int = 100, sort_by: str = "NAME") -> List[Dict[str, str]]:
        root = self._call(
            "namecheap.domains.getList",
            {"Page": str(page), "PageSize": str(page_size), "SortBy": sort_by},
        )

        domains = []
        for item in root.findall(".//{*}Domain"):
            domains.append(
                {
                    "id": item.attrib.get("ID", ""),
                    "name": item.attrib.get("Name", ""),
                    "created": item.attrib.get("Created", ""),
                    "expires": item.attrib.get("Expires", ""),
                    "isExpired": item.attrib.get("IsExpired", ""),
                    "isLocked": item.attrib.get("IsLocked", ""),
                    "autoRenew": item.attrib.get("AutoRenew", ""),
                    "whoisGuard": item.attrib.get("WhoisGuard", ""),
                }
            )
        return domains

    def list_dns_records(self, domain: str) -> List[Dict[str, str]]:
        sld, tld = self.split_domain(domain)
        root = self._call("namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld})
        records = []
        for host in root.findall(".//{*}Host"):
            records.append(
                {
                    "host_id": host.attrib.get("HostId", ""),
                    "name": host.attrib.get("Name", ""),
                    "type": host.attrib.get("Type", ""),
                    "address": host.attrib.get("Address", ""),
                    "mx_pref": host.attrib.get("MXPref", ""),
                    "ttl": host.attrib.get("TTL", ""),
                }
            )
        return records

    def _set_hosts(self, domain: str, records: List[Dict[str, str]]) -> bool:
        sld, tld = self.split_domain(domain)
        params = {"SLD": sld, "TLD": tld}

        for index, record in enumerate(records, start=1):
            params[f"HostName{index}"] = record["name"]
            params[f"RecordType{index}"] = record["type"]
            params[f"Address{index}"] = record["address"]
            if record.get("mx_pref") not in ("", None):
                params[f"MXPref{index}"] = str(record["mx_pref"])
            if record.get("ttl") not in ("", None):
                params[f"TTL{index}"] = str(record["ttl"])

        root = self._call("namecheap.domains.dns.setHosts", params)
        result = root.find(".//{*}DomainDNSSetHostsResult")
        return result is not None and result.attrib.get("IsSuccess", "").lower() == "true"

    def ensure_namecheap_dns(self, domain: str) -> bool:
        sld, tld = self.split_domain(domain)
        root = self._call("namecheap.domains.dns.setDefault", {"SLD": sld, "TLD": tld})
        result = root.find(".//{*}DomainDNSSetDefaultResult")
        return result is not None and result.attrib.get("Updated", "").lower() == "true"


def is_valid_domain_name(value: str) -> bool:
    return bool(DOMAIN_RE.match((value or '').strip().lower()))


def is_valid_selector_name(value: str) -> bool:
    return bool(SELECTOR_RE.match((value or '').strip()))


def generate_dkim_keypair_local(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_b64 = base64.b64encode(public_der).decode('ascii')
    return private_pem, public_b64


def split_for_dns(value: str, chunk: int = 200) -> str:
    parts = [value[i:i + chunk] for i in range(0, len(value), chunk)]
    return ' '.join([f'"{part}"' for part in parts])


def ssh_connect_sftp(host: str, port: int, user: str, password: str, timeout: int = 20):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    sftp = client.open_sftp()
    return client, sftp


def sftp_mkdirs(sftp: paramiko.SFTPClient, path: str):
    path = (path or '').replace('\\', '/').strip()
    if not path:
        return

    is_abs = path.startswith('/')
    parts = [part for part in path.split('/') if part]
    current = '/' if is_abs else '.'
    for part in parts:
        nxt = posixpath.join(current, part) if current != '.' else part
        try:
            sftp.stat(nxt)
        except Exception:
            sftp.mkdir(nxt)
        current = nxt


def sftp_upload_bytes(sftp: paramiko.SFTPClient, remote_path: str, data: bytes):
    remote_path = (remote_path or '').replace('\\', '/').strip()
    if not remote_path:
        raise ValueError('Empty remote path.')

    remote_dir = posixpath.dirname(remote_path)
    if remote_dir and remote_dir not in ('.', '/'):
        sftp_mkdirs(sftp, remote_dir)

    with sftp.open(remote_path, 'wb') as file_handle:
        file_handle.write(data)


def clean_int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def run_dkim_generation(payload: dict):
    ssh_host = (payload.get('sshHost') or '').strip()
    ssh_user = (payload.get('sshUser') or '').strip()
    ssh_pass = payload.get('sshPass') or ''
    ssh_port = clean_int(payload.get('sshPort', 22), 22)
    ssh_timeout = clean_int(payload.get('sshTimeout', 20), 20)
    dkim_filename = (payload.get('dkimFilename') or 'dkim.pem').strip() or 'dkim.pem'
    key_size = clean_int(payload.get('keySize', 2048), 2048)

    if key_size not in (1024, 2048, 4096):
        raise ValueError('Key size must be 1024, 2048, or 4096.')
    if not ssh_host or not ssh_user:
        raise ValueError('Missing SSH host or username.')

    raw_domains = payload.get('domains') or []
    pairs: List[tuple[str, str]] = []
    for item in raw_domains:
        if not isinstance(item, dict):
            continue
        domain = (item.get('domain') or '').strip().lower()
        selector = (item.get('selector') or 'dkim').strip() or 'dkim'
        if domain:
            pairs.append((domain, selector))

    if not pairs:
        raise ValueError('Please provide at least one domain.')

    client = None
    sftp = None
    results = []
    try:
        client, sftp = ssh_connect_sftp(ssh_host, ssh_port, ssh_user, ssh_pass, timeout=ssh_timeout)
        for domain, selector in pairs:
            try:
                if not is_valid_domain_name(domain):
                    raise ValueError(f'Invalid domain format: {domain}')
                if not is_valid_selector_name(selector):
                    raise ValueError(f'Invalid selector format: {selector}')

                private_pem, public_b64 = generate_dkim_keypair_local(key_size=key_size)
                remote_dir = posixpath.join(REMOTE_BASE_DIR.rstrip('/'), domain)
                remote_path = posixpath.join(remote_dir, dkim_filename)
                sftp_upload_bytes(sftp, remote_path, private_pem)

                record_value = f'v=DKIM1; k=rsa; p={public_b64}'
                results.append({
                    'domain': domain,
                    'selector': selector,
                    'remotePath': remote_path,
                    'recordHostShort': f'{selector}._domainkey',
                    'recordHostFull': f'{selector}._domainkey.{domain}',
                    'recordValue': record_value,
                    'recordValueSplit': split_for_dns(record_value, chunk=200),
                    'publicKey': public_b64,
                    'ok': True,
                })
            except Exception as exc:
                results.append({
                    'domain': domain or '(empty)',
                    'selector': selector or '(empty)',
                    'remotePath': '',
                    'recordHostShort': f'{selector}._domainkey' if selector else '',
                    'recordHostFull': f'{selector}._domainkey.{domain}' if selector and domain else '',
                    'recordValue': '',
                    'recordValueSplit': '',
                    'publicKey': '',
                    'ok': False,
                    'error': str(exc),
                })
        return {
            'ok': True,
            'sshSummary': f'Connected to {ssh_host}:{ssh_port} (SFTP).',
            'items': results,
        }
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass


def run_pmta_config_polling(payload: dict):
    ssh_host = (payload.get('sshHost') or '').strip()
    ssh_user = (payload.get('sshUser') or '').strip()
    ssh_pass = payload.get('sshPass') or ''
    ssh_port = clean_int(payload.get('sshPort', 22), 22)
    ssh_timeout = clean_int(payload.get('sshTimeout', 20), 20)
    config_content = payload.get('configContent') or ''

    if not ssh_host or not ssh_user:
        raise ValueError('Missing SSH host or username.')
    if not str(config_content).strip():
        raise ValueError('Generated PowerMTA config is empty.')

    client = None
    sftp = None
    try:
        client, sftp = ssh_connect_sftp(ssh_host, ssh_port, ssh_user, ssh_pass, timeout=ssh_timeout)
        sftp_upload_bytes(sftp, PMTA_REMOTE_CONFIG_PATH, str(config_content).encode('utf-8'))
        return {
            'ok': True,
            'message': f'PowerMTA config was uploaded to {PMTA_REMOTE_CONFIG_PATH} on {ssh_host}:{ssh_port}.',
            'remotePath': PMTA_REMOTE_CONFIG_PATH,
        }
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass


def normalize_namecheap_config(payload: dict) -> Dict[str, object]:
    payload = payload or {}
    return {
        "token": str(payload.get("token") or "").strip(),
        "username": str(payload.get("username") or "").strip(),
        "password": str(payload.get("password") or ""),
        "apiKey": str(payload.get("apiKey") or "").strip(),
        "clientIp": str(payload.get("clientIp") or "").strip(),
        "sandbox": bool(payload.get("sandbox")),
        "lastDomains": payload.get("lastDomains") if isinstance(payload.get("lastDomains"), list) else [],
        "lastCheckedAt": str(payload.get("lastCheckedAt") or "").strip(),
    }


def build_namecheap_client(payload: dict) -> NamecheapClient:
    config = normalize_namecheap_config(payload)
    if not config["token"]:
        raise ValueError("Namecheap token / ApiUser is required.")
    if not config["username"]:
        raise ValueError("Namecheap username is required.")
    if not config["apiKey"]:
        raise ValueError("Namecheap API key is required.")
    if not config["clientIp"]:
        raise ValueError("Namecheap client IP is required.")
    return NamecheapClient(
        api_user=str(config["token"]),
        api_key=str(config["apiKey"]),
        username=str(config["username"]),
        client_ip=str(config["clientIp"]),
        sandbox=bool(config["sandbox"]),
    )


def extract_relative_host(fqdn: str, domain: str) -> str:
    clean_fqdn = (fqdn or "").strip().lower().rstrip(".")
    clean_domain = (domain or "").strip().lower().rstrip(".")
    if not clean_fqdn or not clean_domain:
        return ""
    if clean_fqdn == clean_domain:
        return "@"
    suffix = f".{clean_domain}"
    if clean_fqdn.endswith(suffix):
        return clean_fqdn[: -len(suffix)] or "@"
    return ""


def upsert_namecheap_record(records: List[Dict[str, str]], new_record: Dict[str, str]):
    new_type = (new_record.get("type") or "").upper()
    new_name = (new_record.get("name") or "").strip().lower()
    new_address = (new_record.get("address") or "").strip()

    replaced = False
    for record in records:
        record_type = (record.get("type") or "").upper()
        record_name = (record.get("name") or "").strip().lower()
        if record_type != new_type or record_name != new_name:
            continue
        if new_type == "MX" and record.get("mx_pref") not in ("", None) and new_record.get("mx_pref") not in ("", None):
            if str(record.get("mx_pref")) != str(new_record.get("mx_pref")):
                continue
        record["address"] = new_address
        if "ttl" in new_record:
            record["ttl"] = str(new_record.get("ttl") or "")
        if "mx_pref" in new_record:
            record["mx_pref"] = str(new_record.get("mx_pref") or "")
        replaced = True
        break

    if not replaced:
        records.append(
            {
                "name": new_record.get("name", ""),
                "type": new_type,
                "address": new_address,
                "ttl": str(new_record.get("ttl") or ""),
                "mx_pref": str(new_record.get("mx_pref") or ""),
            }
        )


def build_required_namecheap_records(payload: dict) -> List[Dict[str, str]]:
    domain = str(payload.get("domain") or "").strip().lower()
    root_ip = str(payload.get("ipAddress") or "").strip()
    helo = str(payload.get("helo") or "").strip().lower()
    selector = str(payload.get("selector") or "dkim").strip() or "dkim"
    public_key = str(payload.get("publicKey") or "").strip()
    spf = str(payload.get("spf") or "").strip()
    dmarc = str(payload.get("dmarc") or "").strip()
    ttl = str(payload.get("ttl") or 1800)

    if not domain:
        raise ValueError("Domain is required for Namecheap polling.")
    if not root_ip:
        raise ValueError("A record IP is required for Namecheap polling.")
    if not public_key:
        raise ValueError("DKIM public key is required before polling Namecheap.")
    if not spf:
        raise ValueError("SPF value is required before polling Namecheap.")
    if not dmarc:
        raise ValueError("DMARC value is required before polling Namecheap.")

    records = [
        {"name": "@", "type": "A", "address": root_ip, "ttl": ttl},
        {"name": "@", "type": "TXT", "address": spf, "ttl": ttl},
        {"name": f"{selector}._domainkey", "type": "TXT", "address": f"v=DKIM1; k=rsa; p={public_key}", "ttl": ttl},
        {"name": "_dmarc", "type": "TXT", "address": dmarc, "ttl": ttl},
    ]

    mx_target = helo or f"mail.{domain}"
    records.append({"name": "@", "type": "MX", "address": mx_target, "mx_pref": "10", "ttl": ttl})

    mail_host = extract_relative_host(mx_target, domain)
    if mail_host:
        records.append({"name": mail_host, "type": "A", "address": root_ip, "ttl": ttl})

    return records


def poll_namecheap_dns(payload: dict):
    client = build_namecheap_client(payload.get("config") or {})
    domain = str(payload.get("domain") or "").strip().lower()
    if not domain:
        raise ValueError("Domain is required.")

    existing_records = client.list_dns_records(domain)
    merged_records = list(existing_records)
    required_records = build_required_namecheap_records(payload)
    for record in required_records:
        upsert_namecheap_record(merged_records, record)

    success = client._set_hosts(domain, merged_records)
    if not success:
        raise NamecheapAPIError("Namecheap did not confirm DNS update success.")

    return {
        "ok": True,
        "domain": domain,
        "appliedRecords": required_records,
        "message": f"Namecheap DNS records were updated for {domain}.",
    }

HTML = r'''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Mail Infrastructure & PowerMTA Dashboard</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #121a2b;
      --panel-2: #18233a;
      --line: #273552;
      --text: #e8eefc;
      --muted: #9fb0d3;
      --primary: #58a6ff;
      --success: #27c281;
      --warning: #f4b740;
      --danger: #ff6b6b;
      --shadow: 0 10px 30px rgba(0,0,0,.25);
      --radius: 16px;
    }

    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Tahoma, Arial, sans-serif;
    }
    body { padding: 20px; }
    .app { max-width: 1600px; margin: 0 auto; }

    .topbar {
      display: flex;
      gap: 16px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .title-wrap h1 { margin: 0 0 6px; font-size: 30px; }
    .title-wrap p { margin: 0; color: var(--muted); }

    .actions { display: flex; gap: 10px; flex-wrap: wrap; }
    button, .btn {
      border: 1px solid var(--line);
      background: var(--panel-2);
      color: var(--text);
      padding: 10px 14px;
      border-radius: 12px;
      cursor: pointer;
      font-size: 14px;
      transition: .2s ease;
      box-shadow: var(--shadow);
    }
    button:hover, .btn:hover { transform: translateY(-1px); border-color: var(--primary); }
    button:disabled, .btn:disabled {
      opacity: .55;
      cursor: not-allowed;
      transform: none;
      border-color: var(--line);
    }
    .btn-primary { background: var(--primary); color: #08111f; border-color: transparent; font-weight: bold; }
    .btn-success { background: var(--success); color: #07150f; border-color: transparent; font-weight: bold; }
    .btn-warning { background: var(--warning); color: #201400; border-color: transparent; font-weight: bold; }
    .btn-danger { background: var(--danger); color: #240909; border-color: transparent; font-weight: bold; }

    .grid { display: grid; gap: 16px; }
    .grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }

    .card {
      background: linear-gradient(180deg, rgba(255,255,255,.02), rgba(255,255,255,.01));
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 16px;
      box-shadow: var(--shadow);
    }
    .card h2, .card h3, .card h4 { margin: 0 0 12px; }
    .sub { color: var(--muted); font-size: 13px; margin-bottom: 14px; }
    .divider { height: 1px; background: var(--line); margin: 16px 0; }
    .muted { color: var(--muted); }
    .small { font-size: 12px; }
    .ltr { direction: ltr; text-align: left; }

    .stat {
      padding: 16px;
      border-radius: 16px;
      background: var(--panel);
      border: 1px solid var(--line);
    }
    .stat .label { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
    .stat .value { font-size: 30px; font-weight: bold; }

    label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
    input, select, textarea {
      width: 100%;
      background: #0f1728;
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px 13px;
      font-size: 14px;
      outline: none;
    }
    input:focus, select:focus, textarea:focus { border-color: var(--primary); }
    textarea { min-height: 120px; resize: vertical; line-height: 1.5; }
    .textarea-lg { min-height: 340px; font-family: Consolas, monospace; direction: ltr; text-align: left; }
    .readonly { opacity: .92; }

    .row { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }

    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: bold;
      border: 1px solid transparent;
    }
    .status.ok { background: rgba(39,194,129,.12); color: #7ff0bb; border-color: rgba(39,194,129,.35); }
    .status.warn { background: rgba(244,183,64,.12); color: #ffd97d; border-color: rgba(244,183,64,.35); }
    .status.err { background: rgba(255,107,107,.12); color: #ff9d9d; border-color: rgba(255,107,107,.35); }
    .status.muted { background: rgba(159,176,211,.12); color: #cfdbf7; border-color: rgba(159,176,211,.25); }
    .status.delete {
      background: rgba(255,107,107,.12);
      color: #ff9d9d;
      border-color: rgba(255,107,107,.35);
      cursor: pointer;
    }

    .notice {
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #0f1728;
      color: var(--muted);
      font-size: 13px;
    }
    .notice.ok { border-color: rgba(39,194,129,.35); color: #7ff0bb; }
    .notice.warn { border-color: rgba(244,183,64,.35); color: #ffd97d; }
    .notice.err { border-color: rgba(255,107,107,.35); color: #ffb1b1; }

    .qm-layout { display: grid; grid-template-columns: 1fr; gap: 14px; align-items: start; }
    .qm-layout.with-workspace { grid-template-columns: 1fr 1fr; }
    .tree-shell.full-width { grid-column: 1 / -1; }
    .workspace-shell.hidden-panel { display: none; }
    .tree-shell, .workspace-shell {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #0f1728;
      padding: 14px;
    }
    .section-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }
    .inline-actions { display: flex; gap: 8px; flex-wrap: wrap; }

    .tree-node {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: #101a2d;
      margin-bottom: 10px;
      overflow: hidden;
    }
    .tree-node-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      cursor: pointer;
    }
    .tree-node-header:hover { background: rgba(255,255,255,.02); }
    .tree-node-title { font-weight: 700; }
    .tree-node-sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .tree-node-children { padding: 0 10px 10px 22px; display: grid; gap: 8px; }

    .tree-leaf {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #0d1526;
      padding: 10px 12px;
      cursor: pointer;
    }
    .tree-leaf.active, .tree-node.active { border-color: var(--primary); box-shadow: inset 0 0 0 1px var(--primary); }
    .tree-leaf-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .tree-leaf-title { font-weight: 600; }
    .tree-leaf-meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .tree-indent { margin-left: 14px; border-left: 1px dashed var(--line); padding-left: 12px; display: grid; gap: 8px; }
    .hidden { display: none !important; }

    .overview-grid { display: grid; grid-template-columns: 1.1fr .9fr; gap: 14px; }
    .overview-stack { display: grid; gap: 12px; }
    .mini-card { border: 1px solid var(--line); border-radius: 14px; background: #0f1728; padding: 14px; }
    .kv { display: grid; gap: 8px; }
    .kv-row { display: flex; justify-content: space-between; gap: 12px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,.05); }
    .kv-row:last-child { border-bottom: 0; }
    .muted-box { border: 1px dashed var(--line); border-radius: 12px; padding: 12px; color: var(--muted); }
    .domain-list-compact { display: grid; gap: 8px; }
    .domain-row { border: 1px solid var(--line); border-radius: 12px; background: #0d1526; padding: 10px 12px; overflow: hidden; }
    .domain-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .btn-sm { padding: 6px 10px; font-size: 12px; box-shadow: none; }
    .clamp-note {
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
      overflow: hidden;
      word-break: break-word;
      overflow-wrap: anywhere;
      white-space: normal;
    }
    .break-safe {
      word-break: break-word;
      overflow-wrap: anywhere;
      white-space: normal;
    }
    .domain-row-top { display: flex; justify-content: space-between; gap: 12px; }
    .registry-filters { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 14px 0; }
    .group-block { border: 1px solid var(--line); border-radius: 14px; padding: 12px; background: rgba(255,255,255,.01); }
    .group-title { font-weight: 700; margin-bottom: 8px; }
    .group-subtitle { color: var(--muted); font-size: 12px; margin-bottom: 10px; }
    .linked-ip-list { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
    .registry-monitor { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 12px 0 8px; }
    .registry-stat {
      padding: 10px 12px;
      border-radius: 14px;
      background: var(--panel);
      border: 1px solid var(--line);
    }
    .registry-stat .label { color: var(--muted); font-size: 12px; margin-bottom: 6px; }
    .registry-stat .value { font-size: 20px; font-weight: bold; }
    .pagination-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin: 12px 0;
      flex-wrap: wrap;
    }
    .pagination-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .pagination-info { color: var(--muted); font-size: 12px; }

    .tabs { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
    .tab {
      padding: 9px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--panel);
      cursor: pointer;
      font-size: 13px;
    }
    .tab.active { background: var(--primary); color: #08111f; border-color: transparent; font-weight: bold; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }

    .workspace-nav {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 14px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255,255,255,.06);
    }
    .workspace-nav-btn {
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      cursor: pointer;
      font-size: 13px;
      box-shadow: none;
    }
    .workspace-nav-btn.active {
      background: var(--primary);
      color: #08111f;
      border-color: transparent;
      font-weight: bold;
    }

    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 8px; font-size: 13px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: normal; }

    .checklist { display: grid; gap: 8px; }
    .check {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #0f1728;
    }

    .footer-space { height: 40px; }

    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(3, 9, 18, .78);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
      z-index: 999;
    }
    .modal-overlay.show { display: flex; }
    .modal {
      width: min(980px, 100%);
      background: linear-gradient(180deg, rgba(18,26,43,.98), rgba(15,23,40,.98));
      border: 1px solid var(--line);
      border-radius: 22px;
      box-shadow: 0 30px 80px rgba(0,0,0,.45);
      overflow: hidden;
    }
    .modal.modal-xl {
      width: min(1380px, 100%);
      max-height: calc(100vh - 48px);
      display: flex;
      flex-direction: column;
    }
    .modal-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      padding: 18px 20px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      background: rgba(255,255,255,.02);
    }
    .modal-header h3 { margin: 0 0 6px; }
    .modal-header p { margin: 0; color: var(--muted); font-size: 13px; }
    .modal-close {
      min-width: 42px;
      height: 42px;
      border-radius: 12px;
      font-size: 20px;
      line-height: 1;
      padding: 0;
      box-shadow: none;
    }
    .modal-body { padding: 20px; }
    .modal.modal-xl .modal-body {
      overflow: auto;
    }
    .modal-actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
      padding: 0 20px 20px;
    }
    .modal-textarea {
      min-height: 360px;
      font-family: Consolas, monospace;
      direction: ltr;
      text-align: left;
    }
    .modal-toolbar {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 14px;
    }
    .bulk-dkim-grid { display: grid; gap: 16px; }
    .bulk-dkim-results { display: grid; gap: 12px; }
    .bulk-dkim-item {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #0f1728;
      padding: 14px;
    }
    .bulk-dkim-item .kv-row strong,
    .bulk-dkim-item pre {
      direction: ltr;
      text-align: left;
    }
    .bulk-dkim-table { width: 100%; border-collapse: collapse; }
    .bulk-dkim-table th, .bulk-dkim-table td {
      border-bottom: 1px solid rgba(255,255,255,.06);
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }
    .bulk-dkim-table th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .06em;
    }
    .bulk-dkim-table input { min-width: 0; }
    .bulk-dkim-table .btn-danger { width: 100%; }
    .bulk-dkim-copy-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .pre-box {
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #0b1220;
      padding: 12px;
      white-space: pre-wrap;
      word-break: break-word;
    }

    @media (max-width: 1200px) {
      .grid-4, .row, .qm-layout, .overview-grid, .registry-monitor { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app">
    <div class="topbar">
      <div class="title-wrap">
        <h1>Mail Infrastructure & PowerMTA Dashboard</h1>
        <p>Manage servers, additional IPs, domains, DKIM/SPF/DMARC/PTR, and PowerMTA config parsing in one place.</p>
      </div>
      <div class="actions">
        <button id="exportBtn">Export JSON</button>
        <button id="importBtn">Import JSON</button>
        <button id="namecheapConfigBtn">NameChip Config</button>
        <button id="domainsRegistryBtn">Domains</button>
        <button id="bulkDkimBtn" class="btn-danger">Bulk DKIM generator</button>
      </div>
    </div>

    <div class="grid grid-4" id="stats"></div>

    <div class="divider"></div>

    <div class="card">
      <h2>Quick Management</h2>
      <div class="sub">Use the tree to move from server to IP to domain. The workspace adapts to the selected level and reduces repeated manual input.</div>
      <div class="qm-layout" id="qmLayout">
        <div class="tree-shell full-width" id="treeShell">
          <div class="section-title">
            <h3>Infrastructure Tree</h3>
            <div class="inline-actions">
              <button id="treeExpandBtn">Expand All</button>
              <button id="treeCollapseBtn">Collapse All</button>
              <button id="addNewBtn" class="btn-primary">Add New</button>
            </div>
          </div>
          <div id="infraTree"></div>
        </div>
        <div class="workspace-shell hidden-panel" id="workspaceShell">
          <div class="section-title">
            <h3 id="workspaceTitle">Server Workspace</h3>
            <span id="workspaceBadge" class="status muted">No selection</span>
          </div>
          <div id="workspaceContent"></div>
        </div>
      </div>
    </div>

    <div class="divider"></div>

    <div class="card">
      <div class="tabs" id="mainTabs">
        <div class="tab active" data-tab="overviewPanel">Overview</div>
        <div class="tab" data-tab="pmtaPanel">PowerMTA Config Studio</div>
        <div class="tab" data-tab="readinessPanel">Readiness</div>
        <div class="tab" data-tab="dnsPanel">DNS Summary</div>
        <div class="tab" data-tab="outputPanel">Generated Output</div>
        <div class="tab" data-tab="domainsRegistryPanel" id="domainsRegistryTab">Domains Registry</div>
      </div>

      <div class="tab-panel active" id="overviewPanel">
        <h2>Overview</h2>
        <div class="sub">A structured view of the selected server, IP, or domain, with hierarchy, readiness, and the most important operational details.</div>
        <div class="overview-grid">
          <div class="overview-stack">
            <div id="overviewHero" class="mini-card">
              <h4>Selection Summary</h4>
              <div class="muted-box">Select a server, IP, or domain from the infrastructure tree to populate this overview.</div>
            </div>
            <div id="overviewHierarchy" class="mini-card">
              <h4>Hierarchy</h4>
              <div class="muted-box">The hierarchy path will appear here.</div>
            </div>
            <div id="overviewDomains" class="mini-card">
              <h4>Linked Domains</h4>
              <div class="muted-box">No linked domains to display yet.</div>
            </div>
          </div>
          <div class="overview-stack">
            <div id="overviewHealth" class="mini-card">
              <h4>Health & Readiness</h4>
              <div class="muted-box">Readiness and quick checks will appear here.</div>
            </div>
            <div id="overviewConfig" class="mini-card">
              <h4>Config Snapshot</h4>
              <div class="muted-box">Core sending configuration will appear here.</div>
            </div>
          </div>
        </div>
      </div>

      <div class="tab-panel" id="pmtaPanel">
        <div class="row">
          <div>
            <label>Target Server for Config Apply</label>
            <select id="pmtaServerSelect"></select>
          </div>
          <div>
            <label>Snapshot Name / Comment</label>
            <input id="pmtaSnapshotName" placeholder="Example: config-2026-03-08" />
          </div>
        </div>
        <div style="margin-top:12px">
          <label>PowerMTA Raw Config</label>
          <textarea id="pmtaConfig" class="textarea-lg" placeholder="Paste PowerMTA config here..."></textarea>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:12px">
          <button id="parsePmtaBtn" class="btn-primary">Parse Config</button>
          <button id="applyPmtaBtn" class="btn-success">Apply to Selected Server</button>
          <button id="validatePmtaBtn" class="btn-warning">Validate</button>
          <button id="clearPmtaBtn">Clear Textarea</button>
        </div>
        <div class="divider"></div>
        <h3>Extracted Config Mapping</h3>
        <div id="pmtaNotices" class="notice">Paste a config and click Parse.</div>
        <div style="overflow:auto; margin-top:12px">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Virtual MTA</th>
                <th>IP</th>
                <th>HELO</th>
                <th>DKIM Path</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="pmtaTableBody"></tbody>
          </table>
        </div>
        <div class="divider"></div>
        <h3>Stored Data vs Config Differences</h3>
        <div id="pmtaDiffs" class="notice">No comparison available yet.</div>
      </div>

      <div class="tab-panel" id="readinessPanel">
        <h2>Domain / Sending Readiness</h2>
        <div class="sub">Readiness is calculated from domain linking, SPF, DKIM, DMARC, PTR, HELO, and PowerMTA mapping.</div>
        <div id="readinessContent" class="notice">Select a domain or apply a config to view readiness.</div>
      </div>

      <div class="tab-panel" id="dnsPanel">
        <h2>DNS Summary</h2>
        <div class="sub">This is an internal review helper and does not replace actual DNS verification from your provider.</div>
        <div id="dnsContent" class="notice">Select a domain to view SPF / DKIM / DMARC / PTR / HELO details.</div>
      </div>

      <div class="tab-panel" id="outputPanel">
        <h2>Generated Output</h2>
        <div class="sub">Generate a clean PowerMTA block or export the full JSON dataset.</div>
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:12px">
          <button id="generateCurrentDomainPmtaBtn">Generate PMTA for Selected Domain</button>
          <button id="generateServerPmtaBtn" class="btn-primary">Generate PMTA for Selected Server</button>
          <button id="pollPmtaInServerBtn" class="btn-warning">Polling in Server</button>
        </div>
        <textarea id="generatedOutput" class="textarea-lg" placeholder="Generated output will appear here"></textarea>
      </div>

      <div class="tab-panel" id="domainsRegistryPanel">
        <h2>Domains Registry</h2>
        <div class="sub">A separate reminder registry for domains, providers, expiry dates, account users, and notes. If a domain is linked to a server in the dashboard, the linked server name is shown automatically.</div>
        <div class="row">
          <div>
            <label>Domain</label>
            <input id="registryDomainName" placeholder="example.com" />
          </div>
          <div>
            <label>Provider</label>
            <input id="registryDomainProvider" placeholder="Namecheap / Cloudflare / GoDaddy" />
          </div>
        </div>
        <div class="row" style="margin-top:12px;">
          <div>
            <label>Expiry Date</label>
            <input id="registryDomainExpiryDate" type="date" />
          </div>
          <div>
            <label>Provider Account User</label>
            <input id="registryDomainAccountUser" placeholder="account@example.com or provider username" />
          </div>
        </div>
        <div style="margin-top:12px;">
          <label>Note</label>
          <textarea id="registryDomainNote" placeholder="Any note related to this domain"></textarea>
        </div>
        <div style="margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;">
          <button id="addRegistryDomainBtn" class="btn-primary">Add Domain</button>
          <button id="updateRegistryDomainBtn" class="btn-warning">Update Selected</button>
          <button id="clearRegistryDomainBtn">Clear Form</button>
        </div>
        <div class="divider"></div>
        <div class="registry-filters">
          <div>
            <label>Filter by Provider</label>
            <select id="registryProviderFilter"></select>
          </div>
          <div>
            <label>Filter by Provider Account User</label>
            <select id="registryAccountFilter"></select>
          </div>
        </div>
        <div id="domainsRegistryContent" class="notice">No registry domains yet.</div>
      </div>
    </div>

    <div class="footer-space"></div>
  </div>

  <div class="modal-overlay" id="jsonModalOverlay">
    <div class="modal">
      <div class="modal-header">
        <div>
          <h3 id="jsonModalTitle">JSON Data Manager</h3>
          <p id="jsonModalSubtitle">View, copy, paste, merge, or replace dashboard data while keeping the current design style.</p>
        </div>
        <button id="jsonModalCloseBtn" class="modal-close">×</button>
      </div>
      <div class="modal-body">
        <div id="jsonModalNotice" class="notice">Ready.</div>
        <div style="margin-top:14px;">
          <label id="jsonModalLabel">JSON Payload</label>
          <textarea id="jsonModalTextarea" class="modal-textarea" placeholder="JSON will appear here or paste new JSON data..."></textarea>
        </div>
        <div class="modal-toolbar" id="jsonModalToolbar"></div>
      </div>
      <div class="modal-actions" id="jsonModalActions"></div>
    </div>
  </div>

  <div class="modal-overlay" id="bulkDkimOverlay">
    <div class="modal modal-xl">
      <div class="modal-header">
        <div>
          <h3>Bulk DKIM generator</h3>
          <p>Standalone DKIM generator injected into the dashboard. It reuses the selected server SSH settings when available and can generate/upload one or many DKIM keys.</p>
        </div>
        <button id="bulkDkimCloseBtn" class="modal-close">×</button>
      </div>
      <div class="modal-body">
        <div id="bulkDkimNotice" class="notice">Ready.</div>
        <div id="bulkDkimContent" style="margin-top:16px;"></div>
      </div>
      <div class="modal-actions">
        <button id="bulkDkimCloseFooterBtn">Close</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="namecheapOverlay">
    <div class="modal">
      <div class="modal-header">
        <div>
          <h3>NameChip Config</h3>
          <p>Save the Namecheap account data locally, test the API connection, and load the domains available in that account.</p>
        </div>
        <button id="namecheapCloseBtn" class="modal-close">×</button>
      </div>
      <div class="modal-body">
        <div id="namecheapNotice" class="notice">Enter your Namecheap account details, then click Try Connection.</div>
        <div class="row" style="margin-top:14px;">
          <div>
            <label>Token / ApiUser</label>
            <input id="namecheapToken" placeholder="Namecheap ApiUser / token" />
          </div>
          <div>
            <label>Username</label>
            <input id="namecheapUsername" placeholder="Namecheap username" />
          </div>
        </div>
        <div class="row" style="margin-top:12px;">
          <div>
            <label>Password</label>
            <input id="namecheapPassword" type="password" placeholder="Saved locally for account reference" />
          </div>
          <div>
            <label>API Key</label>
            <input id="namecheapApiKey" placeholder="Namecheap API key" />
          </div>
        </div>
        <div class="row" style="margin-top:12px;">
          <div>
            <label>Client IP</label>
            <input id="namecheapClientIp" placeholder="Whitelisted IPv4" />
          </div>
          <div>
            <label>Environment</label>
            <select id="namecheapSandbox">
              <option value="false">Production</option>
              <option value="true">Sandbox</option>
            </select>
          </div>
        </div>
        <div style="margin-top:16px;">
          <h4 style="margin-bottom:8px;">Available Domains</h4>
          <div id="namecheapDomainsList" class="notice">Run Try Connection to load domains from the account.</div>
        </div>
      </div>
      <div class="modal-actions">
        <button id="namecheapTryBtn">Try Connection</button>
        <button id="namecheapSaveBtn" class="btn-primary">Save</button>
        <button id="namecheapCloseFooterBtn">Close</button>
      </div>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', async () => {
      const STORAGE_KEY = 'mailInfraDashboardDataV4';
      const PMTA_REMOTE_CONFIG_PATH = '/etc/pmta/config';
      const state = {
        data: defaultData(),
        selected: { type: null, id: null },
        pmtaParsed: null,
        treeCollapsed: false,
        workspaceMode: 'auto',
        showWorkspace: false,
        expandedServers: {},
        expandedIps: {},
        selectedRegistryDomainId: null,
        registryPage: 1,
        registryPageSize: 5,
        modalMode: null,
        bulkDkimResults: null,
        namecheapDomains: [],
      };

      async function apiGetData() {
        const response = await fetch('/api/data');
        if (!response.ok) throw new Error('Failed to load data from backend');
        return await response.json();
      }

      async function apiSaveData(payload) {
        const response = await fetch('/api/data', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) throw new Error('Failed to save data into backend');
        return await response.json();
      }

      async function apiResetData() {
        const response = await fetch('/api/data', { method: 'DELETE' });
        if (!response.ok) throw new Error('Failed to clear backend data');
        return await response.json();
      }

      async function apiCheckSsh(payload) {
        const response = await fetch('/api/dkim/check-ssh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'SSH check failed');
        return data;
      }

      async function apiGenerateDkim(payload) {
        const response = await fetch('/api/dkim/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'DKIM generation failed');
        return data;
      }

      async function apiPollPmtaConfig(payload) {
        const response = await fetch('/api/pmta/poll-config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'PowerMTA config polling failed');
        return data;
      }

      async function apiTryNamecheapConnection(payload) {
        const response = await fetch('/api/namecheap/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Namecheap connection failed');
        return data;
      }

      async function apiPollNamecheapDomain(payload) {
        const response = await fetch('/api/namecheap/poll-domain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Namecheap DNS polling failed');
        return data;
      }

      function uid(prefix = 'id') {
        return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
      }

      function defaultData() {
        return {
          servers: [],
          ips: [],
          domains: [],
          domainRegistry: [],
          snapshots: [],
          domainDraftsByIp: {},
          namecheapConfig: {
            token: '',
            username: '',
            password: '',
            apiKey: '',
            clientIp: '',
            sandbox: false,
            lastDomains: [],
            lastCheckedAt: '',
          },
        };
      }

      function safeArray(value) {
        return Array.isArray(value) ? value : [];
      }

      function loadDataFromBackendObject(obj) {
        const parsed = obj || defaultData();
        return {
          ...defaultData(),
          ...parsed,
          servers: safeArray(parsed.servers),
          ips: safeArray(parsed.ips),
          domains: safeArray(parsed.domains),
          domainRegistry: safeArray(parsed.domainRegistry),
          snapshots: safeArray(parsed.snapshots),
          domainDraftsByIp: parsed.domainDraftsByIp && typeof parsed.domainDraftsByIp === 'object' ? parsed.domainDraftsByIp : {},
          namecheapConfig: parsed.namecheapConfig && typeof parsed.namecheapConfig === 'object'
            ? { ...defaultData().namecheapConfig, ...parsed.namecheapConfig }
            : defaultData().namecheapConfig,
        };
      }

      function persistDataToLocalCache(data) {
        try {
          window.localStorage.setItem(STORAGE_KEY, JSON.stringify(loadDataFromBackendObject(data)));
        } catch (error) {
          console.warn('Unable to write local cache:', error);
        }
      }

      function loadDataFromLocalCache() {
        try {
          const raw = window.localStorage.getItem(STORAGE_KEY);
          if (!raw) return null;
          return loadDataFromBackendObject(JSON.parse(raw));
        } catch (error) {
          console.warn('Unable to read local cache:', error);
          return null;
        }
      }

      function clearDataFromLocalCache() {
        try {
          window.localStorage.removeItem(STORAGE_KEY);
        } catch (error) {
          console.warn('Unable to clear local cache:', error);
        }
      }

      function hasMeaningfulData(data) {
        const normalized = loadDataFromBackendObject(data);
        return Boolean(
          normalized.servers.length ||
          normalized.ips.length ||
          normalized.domains.length ||
          normalized.domainRegistry.length ||
          normalized.snapshots.length ||
          Object.keys(normalized.domainDraftsByIp || {}).length
        );
      }

      async function saveData() {
        await apiSaveData(state.data);
        persistDataToLocalCache(state.data);
        renderAll();
      }

      function getServerById(serverId = '') {
        return state.data?.servers?.find(server => server.id === serverId) || null;
      }

      function getServerSshSettings(server = null) {
        return {
          sshHost: server?.sshHost || '',
          sshPort: String(server?.sshPort || 22),
          sshTimeout: String(server?.sshTimeout || 20),
          sshUser: server?.sshUser || '',
          sshPass: server?.sshPass || '',
          dkimFilename: server?.dkimFilename || 'dkim.pem',
          keySize: String(server?.keySize || 2048),
        };
      }

      function collectSshSettingsFromForm() {
        return {
          sshHost: document.getElementById('serverSshHost')?.value.trim() || '',
          sshPort: document.getElementById('serverSshPort')?.value.trim() || '22',
          sshTimeout: document.getElementById('serverSshTimeout')?.value.trim() || '20',
          sshUser: document.getElementById('serverSshUser')?.value.trim() || '',
          sshPass: document.getElementById('serverSshPass')?.value || '',
          dkimFilename: document.getElementById('serverDkimFilename')?.value.trim() || 'dkim.pem',
          keySize: document.getElementById('serverKeySize')?.value || '2048',
        };
      }

      function validateSshSettings(settings) {
        if (!settings.sshHost) throw new Error('Please enter SSH host');
        if (!settings.sshUser) throw new Error('Please enter SSH username');
        if (!settings.sshPass) throw new Error('Please enter SSH password');
        return settings;
      }

      function escapeHtml(str = '') {
        return String(str)
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#039;');
      }

      function isValidIPv4(ip = '') {
        const parts = ip.trim().split('.');
        if (parts.length !== 4) return false;
        return parts.every(p => /^\d+$/.test(p) && +p >= 0 && +p <= 255);
      }

      function isValidDomain(domain = '') {
        return /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/.test(domain.trim());
      }

      function normalizeDomain(value = '') {
        return value.trim().toLowerCase();
      }

      function extractDomainFromPtr(ptr = '') {
        const clean = normalizeDomain(ptr);
        if (!clean) return '';
        if (clean.startsWith('mail.')) return clean.slice(5);
        return clean.replace(/^[^.]+\./, '');
      }

      function generateDmarcValue(domain) {
        return domain ? `v=DMARC1; p=none; rua=mailto:dmarc@${domain}` : '';
      }

      function generateVmtaName(domain) {
        const base = normalizeDomain(domain)
          .replace(/\.[^.]+$/, '')
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .replace(/-{2,}/g, '-');
        return base ? `pmta-${base}` : '';
      }

      function isValidPemPath(domain, path = '') {
        return !!path && path.trim() === `/root/${normalizeDomain(domain)}/dkim.pem`;
      }

      function openJsonModal(mode, payload = '') {
        state.modalMode = mode;
        const overlay = document.getElementById('jsonModalOverlay');
        const title = document.getElementById('jsonModalTitle');
        const subtitle = document.getElementById('jsonModalSubtitle');
        const label = document.getElementById('jsonModalLabel');
        const textarea = document.getElementById('jsonModalTextarea');
        const actions = document.getElementById('jsonModalActions');
        const toolbar = document.getElementById('jsonModalToolbar');
        const notice = document.getElementById('jsonModalNotice');
        if (!overlay || !title || !subtitle || !label || !textarea || !actions || !toolbar || !notice) return;

        textarea.value = payload;
        toolbar.innerHTML = '';
        notice.className = 'notice';

        if (mode === 'export') {
          title.textContent = 'Export JSON Data';
          subtitle.textContent = 'This popup shows the full current dataset as JSON. You can copy it, review it, or download it.';
          label.textContent = 'Current JSON Data';
          notice.textContent = 'Export ready. You can copy the JSON or download it as a file.';
          actions.innerHTML = `
            <button id="copyJsonBtn">Copy JSON</button>
            <button id="downloadJsonBtn" class="btn-success">Download JSON</button>
            <button id="closeJsonModalBtn">Close</button>
          `;
        } else {
          title.textContent = 'Import JSON Data';
          subtitle.textContent = 'Paste JSON here. Use Add Data to merge into the old dataset, or Import New to replace all existing stored data.';
          label.textContent = 'Paste JSON Data';
          notice.textContent = 'Valid JSON structure is required. Supported keys: servers, ips, domains, domainRegistry, snapshots, and domainDraftsByIp.';
          actions.innerHTML = `
            <button id="mergeJsonBtn" class="btn-primary">Add Data</button>
            <button id="replaceJsonBtn" class="btn-warning">Import New</button>
            <button id="closeJsonModalBtn">Close</button>
          `;
          toolbar.innerHTML = `<button id="formatJsonBtn">Format JSON</button><button id="clearJsonTextareaBtn">Clear</button>`;
        }

        overlay.classList.add('show');
      }

      function closeJsonModal() {
        const overlay = document.getElementById('jsonModalOverlay');
        const textarea = document.getElementById('jsonModalTextarea');
        const notice = document.getElementById('jsonModalNotice');
        if (overlay) overlay.classList.remove('show');
        if (textarea) textarea.value = '';
        if (notice) {
          notice.className = 'notice';
          notice.textContent = 'Ready.';
        }
        state.modalMode = null;
      }

      function setJsonModalNotice(message, type = 'default') {
        const notice = document.getElementById('jsonModalNotice');
        if (!notice) return;
        notice.className = type === 'ok' ? 'notice ok' : type === 'warn' ? 'notice warn' : type === 'err' ? 'notice err' : 'notice';
        notice.textContent = message;
      }

      function setBulkDkimNotice(message, type = 'default') {
        const notice = document.getElementById('bulkDkimNotice');
        if (!notice) return;
        notice.className = type === 'ok' ? 'notice ok' : type === 'warn' ? 'notice warn' : type === 'err' ? 'notice err' : 'notice';
        notice.textContent = message;
      }

      function setNamecheapNotice(message, type = 'default') {
        const notice = document.getElementById('namecheapNotice');
        if (!notice) return;
        notice.className = type === 'ok' ? 'notice ok' : type === 'warn' ? 'notice warn' : type === 'err' ? 'notice err' : 'notice';
        notice.textContent = message;
      }

      function getNamecheapConfig() {
        return { ...defaultData().namecheapConfig, ...(state.data.namecheapConfig || {}) };
      }

      function renderNamecheapDomains(domains = []) {
        const list = document.getElementById('namecheapDomainsList');
        if (!list) return;
        if (!domains.length) {
          list.className = 'notice';
          list.textContent = 'No domains loaded yet.';
          return;
        }
        list.className = 'pre-box';
        list.innerHTML = domains.map(domain => {
          const name = escapeHtml(domain.name || '');
          const expires = escapeHtml(domain.expires || '-');
          return `<div style="padding:4px 0;"><strong>${name}</strong> <span class="muted">· expires ${expires}</span></div>`;
        }).join('');
      }

      function fillNamecheapModal() {
        const config = getNamecheapConfig();
        const domains = Array.isArray(config.lastDomains) ? config.lastDomains : [];
        const token = document.getElementById('namecheapToken');
        const username = document.getElementById('namecheapUsername');
        const password = document.getElementById('namecheapPassword');
        const apiKey = document.getElementById('namecheapApiKey');
        const clientIp = document.getElementById('namecheapClientIp');
        const sandbox = document.getElementById('namecheapSandbox');
        if (token) token.value = config.token || '';
        if (username) username.value = config.username || '';
        if (password) password.value = config.password || '';
        if (apiKey) apiKey.value = config.apiKey || '';
        if (clientIp) clientIp.value = config.clientIp || '';
        if (sandbox) sandbox.value = config.sandbox ? 'true' : 'false';
        renderNamecheapDomains(domains);
        state.namecheapDomains = domains;
      }

      function collectNamecheapConfigFromModal() {
        return {
          token: document.getElementById('namecheapToken')?.value.trim() || '',
          username: document.getElementById('namecheapUsername')?.value.trim() || '',
          password: document.getElementById('namecheapPassword')?.value || '',
          apiKey: document.getElementById('namecheapApiKey')?.value.trim() || '',
          clientIp: document.getElementById('namecheapClientIp')?.value.trim() || '',
          sandbox: document.getElementById('namecheapSandbox')?.value === 'true',
          lastDomains: state.namecheapDomains || [],
          lastCheckedAt: new Date().toISOString(),
        };
      }

      function validateNamecheapConfig(config) {
        if (!config.token) throw new Error('Please enter the Namecheap token / ApiUser');
        if (!config.username) throw new Error('Please enter the Namecheap username');
        if (!config.apiKey) throw new Error('Please enter the Namecheap API key');
        if (!config.clientIp) throw new Error('Please enter the whitelisted Namecheap client IP');
        return config;
      }

      function openNamecheapModal() {
        document.getElementById('namecheapOverlay')?.classList.add('show');
        fillNamecheapModal();
        const config = getNamecheapConfig();
        setNamecheapNotice(
          config.lastCheckedAt
            ? `Last checked at ${config.lastCheckedAt}. Run Try Connection again to refresh available domains.`
            : 'Enter your Namecheap account details, then click Try Connection.',
          config.lastCheckedAt ? 'ok' : 'default'
        );
      }

      function closeNamecheapModal() {
        document.getElementById('namecheapOverlay')?.classList.remove('show');
      }

      async function saveNamecheapConfig() {
        const config = validateNamecheapConfig(collectNamecheapConfigFromModal());
        state.data.namecheapConfig = config;
        await saveData();
        setNamecheapNotice('Namecheap configuration saved locally.', 'ok');
      }

      async function tryNamecheapConnection() {
        const config = validateNamecheapConfig(collectNamecheapConfigFromModal());
        setNamecheapNotice('Trying Namecheap connection...', 'warn');
        const result = await apiTryNamecheapConnection(config);
        state.namecheapDomains = result.domains || [];
        state.data.namecheapConfig = {
          ...config,
          lastDomains: state.namecheapDomains,
          lastCheckedAt: new Date().toISOString(),
        };
        renderNamecheapDomains(state.namecheapDomains);
        await saveData();
        setNamecheapNotice(result.message || `Loaded ${state.namecheapDomains.length} domains from Namecheap.`, 'ok');
      }

      function closeBulkDkimModal() {
        document.getElementById('bulkDkimOverlay')?.classList.remove('show');
        setBulkDkimNotice('Ready.');
      }

      function getBulkDkimDefaultDomains(server = null) {
        if (!server) return [{ domain: '', selector: 'dkim' }];
        const linked = state.data.domains
          .filter(domain => domain.serverId === server.id)
          .map(domain => ({ domain: domain.domain || '', selector: domain.selector || 'dkim' }));
        const drafts = state.data.ips
          .filter(ip => ip.serverId === server.id)
          .map(ip => state.data.domainDraftsByIp?.[ip.id])
          .filter(Boolean)
          .map(draft => ({ domain: draft.domain || '', selector: draft.selector || 'dkim' }));
        const merged = [...linked, ...drafts].filter(item => item.domain);
        const unique = [];
        const seen = new Set();
        merged.forEach(item => {
          const key = `${normalizeDomain(item.domain)}__${item.selector || 'dkim'}`;
          if (!seen.has(key)) {
            seen.add(key);
            unique.push({ domain: normalizeDomain(item.domain), selector: item.selector || 'dkim' });
          }
        });
        return unique.length ? unique : [{ domain: '', selector: 'dkim' }];
      }

      function buildBulkDkimRows(rows = [{ domain: '', selector: 'dkim' }]) {
        return rows.map((row, index) => `
          <tr>
            <td><input data-bulk-domain value="${escapeHtml(row.domain || '')}" placeholder="example.com" /></td>
            <td><input data-bulk-selector value="${escapeHtml(row.selector || 'dkim')}" placeholder="dkim" /></td>
            <td><button type="button" class="btn-danger" data-bulk-remove-row="${index}">Remove</button></td>
          </tr>
        `).join('');
      }

      function renderBulkDkimModal(server = null, rows = null) {
        const content = document.getElementById('bulkDkimContent');
        if (!content) return;
        const ssh = getServerSshSettings(server);
        const selectedServerId = server?.id || '';
        const effectiveRows = rows || getBulkDkimDefaultDomains(server);
        const bulkResults = state.bulkDkimResults;

        content.innerHTML = `
          <div class="bulk-dkim-grid">
            <div class="card">
              <h2>SSH / SFTP Settings</h2>
              <div class="sub">These fields mirror DKIM generator settings. Save them in the server workspace to reuse them everywhere.</div>
              <input id="bulkDkimServerId" type="hidden" value="${escapeHtml(selectedServerId)}" />
              <div class="row" style="margin-top:12px;">
                <div>
                  <label>SSH Host</label>
                  <input id="bulkSshHost" value="${escapeHtml(ssh.sshHost)}" placeholder="server.example.com" />
                </div>
                <div>
                  <label>Port</label>
                  <input id="bulkSshPort" type="number" value="${escapeHtml(ssh.sshPort)}" />
                </div>
              </div>
              <div class="row" style="margin-top:12px;">
                <div>
                  <label>Timeout (sec)</label>
                  <input id="bulkSshTimeout" type="number" value="${escapeHtml(ssh.sshTimeout)}" />
                </div>
                <div>
                  <label>Username</label>
                  <input id="bulkSshUser" value="${escapeHtml(ssh.sshUser)}" />
                </div>
              </div>
              <div class="row" style="margin-top:12px;">
                <div>
                  <label>Password</label>
                  <input id="bulkSshPass" type="password" value="${escapeHtml(ssh.sshPass)}" />
                </div>
                <div>
                  <label>DKIM filename</label>
                  <input id="bulkDkimFilename" value="${escapeHtml(ssh.dkimFilename)}" />
                </div>
              </div>
              <div class="row" style="margin-top:12px;">
                <div>
                  <label>Key size</label>
                  <select id="bulkKeySize">
                    <option value="2048" ${ssh.keySize === '2048' ? 'selected' : ''}>2048 (recommended)</option>
                    <option value="1024" ${ssh.keySize === '1024' ? 'selected' : ''}>1024 (legacy)</option>
                    <option value="4096" ${ssh.keySize === '4096' ? 'selected' : ''}>4096</option>
                  </select>
                </div>
                <div>
                  <label>Selected Server</label>
                  <input value="${escapeHtml(server?.name || 'No server selected')}" class="readonly" readonly />
                </div>
              </div>
              <div class="inline-actions" style="margin-top:14px;">
                <button id="bulkCheckSshBtn">Check SSH Connection</button>
                <button id="bulkSaveToServerBtn" class="btn-warning" ${selectedServerId ? '' : 'disabled'}>Save SSH to Selected Server</button>
              </div>
            </div>

            <div class="card">
              <h2>Domains + DKIM Selector</h2>
              <div class="sub">Bulk mode keeps the original DKIM generator behavior. For PTR-driven workflow inside Quick Management, single-domain generation runs automatically.</div>
              <table class="bulk-dkim-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Selector</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody id="bulkDkimRows">${buildBulkDkimRows(effectiveRows)}</tbody>
              </table>
              <div class="inline-actions" style="margin-top:14px;">
                <button id="bulkAddRowBtn">+ Add domain</button>
                <button id="bulkGenerateBtn" class="btn-primary">Generate + Upload</button>
              </div>
            </div>

            <div class="card">
              <h2>Results</h2>
              ${bulkResults?.items?.length ? `
                <div class="sub">${escapeHtml(bulkResults.sshSummary || '')}</div>
                <div class="bulk-dkim-results">
                  ${bulkResults.items.map((item, index) => `
                    <div class="bulk-dkim-item">
                      <div class="kv">
                        <div class="kv-row"><span>Domain</span><strong>${escapeHtml(item.domain)}</strong></div>
                        <div class="kv-row"><span>Selector</span><strong>${escapeHtml(item.selector)}</strong></div>
                        <div class="kv-row"><span>Private key path</span><strong>${escapeHtml(item.remotePath)}</strong></div>
                        <div class="kv-row"><span>Status</span><strong>${item.ok ? 'Uploaded' : 'Failed'}</strong></div>
                        ${item.error ? `<div class="kv-row"><span>Error</span><strong>${escapeHtml(item.error)}</strong></div>` : ''}
                      </div>
                      <div class="pre-box" id="bulkRecordHost_${index}">${escapeHtml(item.recordHostFull || '-')}</div>
                      <div class="pre-box" id="bulkRecordValue_${index}">${escapeHtml(item.recordValue || '-')}</div>
                      <div class="pre-box" id="bulkRecordSplit_${index}">${escapeHtml(item.recordValueSplit || '-')}</div>
                      <div class="bulk-dkim-copy-row">
                        <button data-copy-target="bulkRecordHost_${index}">Copy Host</button>
                        <button data-copy-target="bulkRecordValue_${index}" class="btn-primary">Copy Value</button>
                        <button data-copy-target="bulkRecordSplit_${index}">Copy Split</button>
                      </div>
                    </div>
                  `).join('')}
                </div>
              ` : `<div class="notice">No generated rows yet.</div>`}
            </div>
          </div>
        `;
      }

      function openBulkDkimModal() {
        const server = getCurrentContextServer();
        state.bulkDkimResults = null;
        renderBulkDkimModal(server);
        document.getElementById('bulkDkimOverlay')?.classList.add('show');
        setBulkDkimNotice(server ? `Using SSH defaults from server: ${server.name}` : 'Open a server first to prefill SSH settings automatically.', server ? 'ok' : 'warn');
      }

      function collectBulkDkimPayload() {
        const rows = Array.from(document.querySelectorAll('#bulkDkimRows tr')).map(row => ({
          domain: row.querySelector('[data-bulk-domain]')?.value.trim() || '',
          selector: row.querySelector('[data-bulk-selector]')?.value.trim() || 'dkim',
        })).filter(item => item.domain);

        return {
          serverId: document.getElementById('bulkDkimServerId')?.value || '',
          sshHost: document.getElementById('bulkSshHost')?.value.trim() || '',
          sshPort: document.getElementById('bulkSshPort')?.value.trim() || '22',
          sshTimeout: document.getElementById('bulkSshTimeout')?.value.trim() || '20',
          sshUser: document.getElementById('bulkSshUser')?.value.trim() || '',
          sshPass: document.getElementById('bulkSshPass')?.value || '',
          dkimFilename: document.getElementById('bulkDkimFilename')?.value.trim() || 'dkim.pem',
          keySize: document.getElementById('bulkKeySize')?.value || '2048',
          domains: rows,
        };
      }

      function writeSshSettingsToServer(serverId, payload) {
        const server = getServerById(serverId);
        if (!server) throw new Error('Select a server first');
        server.sshHost = payload.sshHost;
        server.sshPort = Number(payload.sshPort || 22);
        server.sshTimeout = Number(payload.sshTimeout || 20);
        server.sshUser = payload.sshUser;
        server.sshPass = payload.sshPass;
        server.dkimFilename = payload.dkimFilename || 'dkim.pem';
        server.keySize = Number(payload.keySize || 2048);
      }

      async function generateSingleDkimForDomain(serverId, domain) {
        const server = getServerById(serverId);
        if (!server) throw new Error('Please select a server first');
        const payload = { ...validateSshSettings(getServerSshSettings(server)), domains: [{ domain, selector: 'dkim' }] };
        const result = await apiGenerateDkim(payload);
        const item = result.items?.[0];
        if (!item?.ok) throw new Error(item?.error || 'DKIM generation failed');
        return item;
      }

      function getCurrentExportJson() {
        return JSON.stringify(state.data, null, 2);
      }

      function downloadJsonText(filename, content) {
        const blob = new Blob([content], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
      }

      async function copyElementText(elementId) {
        const text = document.getElementById(elementId)?.textContent?.trim() || '';
        if (!text) throw new Error('Nothing to copy');
        await navigator.clipboard.writeText(text);
      }

      function normalizeImportedData(parsed) {
        return {
          ...defaultData(),
          ...parsed,
          servers: safeArray(parsed.servers),
          ips: safeArray(parsed.ips),
          domains: safeArray(parsed.domains),
          domainRegistry: safeArray(parsed.domainRegistry),
          snapshots: safeArray(parsed.snapshots),
          domainDraftsByIp: parsed.domainDraftsByIp && typeof parsed.domainDraftsByIp === 'object' ? parsed.domainDraftsByIp : {},
          namecheapConfig: parsed.namecheapConfig && typeof parsed.namecheapConfig === 'object'
            ? { ...defaultData().namecheapConfig, ...parsed.namecheapConfig }
            : defaultData().namecheapConfig,
        };
      }

      function clone(value) {
        return JSON.parse(JSON.stringify(value));
      }

      function remapImportedDataIds(importedData) {
        const source = clone(normalizeImportedData(importedData));
        const serverMap = {};
        const ipMap = {};
        const domainMap = {};

        source.servers = source.servers.map(server => {
          const newId = uid('srv');
          serverMap[server.id] = newId;
          return { ...server, id: newId };
        });

        source.ips = source.ips.map(ip => {
          const newId = uid('ip');
          ipMap[ip.id] = newId;
          return {
            ...ip,
            id: newId,
            serverId: serverMap[ip.serverId] || ip.serverId,
          };
        });

        source.domains = source.domains.map(domain => {
          const newId = uid('dom');
          domainMap[domain.id] = newId;
          return {
            ...domain,
            id: newId,
            serverId: serverMap[domain.serverId] || domain.serverId,
            ipId: ipMap[domain.ipId] || domain.ipId,
          };
        });

        source.domainRegistry = source.domainRegistry.map(item => ({
          ...item,
          id: uid('regdom')
        }));

        source.snapshots = source.snapshots.map(snapshot => ({
          ...snapshot,
          id: uid('snap'),
          serverId: serverMap[snapshot.serverId] || snapshot.serverId,
        }));

        const remappedDrafts = {};
        Object.entries(source.domainDraftsByIp || {}).forEach(([oldIpId, draft]) => {
          const newIpId = ipMap[oldIpId] || oldIpId;
          remappedDrafts[newIpId] = {
            ...draft,
            ipId: newIpId,
            serverId: serverMap[draft.serverId] || draft.serverId,
          };
        });
        source.domainDraftsByIp = remappedDrafts;

        return source;
      }

      function dedupeRegistryByDomain(items) {
        const map = new Map();
        items.forEach(item => {
          const key = normalizeDomain(item.domain || '');
          if (!key) return;
          map.set(key, item);
        });
        return Array.from(map.values());
      }

      function mergeImportedData(rawImported) {
        const imported = remapImportedDataIds(rawImported);
        const current = clone(state.data);
        const existingServerNames = new Set(current.servers.map(x => String(x.name || '').trim().toLowerCase()));
        const existingIps = new Set(current.ips.map(x => String(x.ip || '').trim()));
        const existingDomains = new Set(current.domains.map(x => normalizeDomain(x.domain || '')));

        current.servers.push(...imported.servers.filter(server => !existingServerNames.has(String(server.name || '').trim().toLowerCase())));
        current.ips.push(...imported.ips.filter(ip => !existingIps.has(String(ip.ip || '').trim())));
        current.domains.push(...imported.domains.filter(domain => !existingDomains.has(normalizeDomain(domain.domain || ''))));
        current.domainRegistry = dedupeRegistryByDomain([...current.domainRegistry, ...imported.domainRegistry]);
        current.snapshots.push(...imported.snapshots);

        Object.entries(imported.domainDraftsByIp || {}).forEach(([ipId, draft]) => {
          if (!current.domainDraftsByIp[ipId]) {
            current.domainDraftsByIp[ipId] = draft;
          }
        });

        if (!current.namecheapConfig?.token && imported.namecheapConfig?.token) {
          current.namecheapConfig = { ...defaultData().namecheapConfig, ...imported.namecheapConfig };
        }

        return current;
      }

      function parseJsonTextarea() {
        const textarea = document.getElementById('jsonModalTextarea');
        const raw = textarea?.value?.trim() || '';
        if (!raw) throw new Error('JSON textarea is empty.');
        const parsed = JSON.parse(raw);
        return normalizeImportedData(parsed);
      }

      async function handleMergeImport() {
        try {
          const imported = parseJsonTextarea();
          state.data = mergeImportedData(imported);
          await apiSaveData(state.data);
          persistDataToLocalCache(state.data);
          setJsonModalNotice('Data merged successfully with the existing dataset.', 'ok');
          renderAll();
        } catch (error) {
          setJsonModalNotice(error.message || 'Failed to merge JSON data.', 'err');
        }
      }

      async function handleReplaceImport() {
        try {
          const imported = parseJsonTextarea();
          state.data = normalizeImportedData(imported);
          state.selected = { type: null, id: null };
          state.pmtaParsed = null;
          state.showWorkspace = false;
          state.workspaceMode = 'auto';
          state.expandedServers = {};
          state.expandedIps = {};
          state.selectedRegistryDomainId = null;
          state.registryPage = 1;
          await apiSaveData(state.data);
          persistDataToLocalCache(state.data);
          setJsonModalNotice('Existing data was replaced successfully with the new JSON dataset.', 'ok');
          renderAll();
        } catch (error) {
          setJsonModalNotice(error.message || 'Failed to import new JSON data.', 'err');
        }
      }

      function copyJsonToClipboard() {
        const textarea = document.getElementById('jsonModalTextarea');
        const value = textarea?.value || '';
        if (!value) {
          setJsonModalNotice('There is no JSON to copy.', 'warn');
          return;
        }
        navigator.clipboard.writeText(value)
          .then(() => setJsonModalNotice('JSON copied to clipboard.', 'ok'))
          .catch(() => setJsonModalNotice('Clipboard copy failed. You can still copy manually.', 'warn'));
      }

      function formatJsonTextarea() {
        try {
          const parsed = parseJsonTextarea();
          const textarea = document.getElementById('jsonModalTextarea');
          if (textarea) textarea.value = JSON.stringify(parsed, null, 2);
          setJsonModalNotice('JSON formatted successfully.', 'ok');
        } catch (error) {
          setJsonModalNotice(error.message || 'Invalid JSON format.', 'err');
        }
      }

      function getCurrentContextServer() {
        if (state.selected.type === 'server') return state.data.servers.find(x => x.id === state.selected.id) || null;
        if (state.selected.type === 'ip') {
          const ip = state.data.ips.find(x => x.id === state.selected.id);
          return ip ? state.data.servers.find(x => x.id === ip.serverId) || null : null;
        }
        if (state.selected.type === 'domain') {
          const domain = state.data.domains.find(x => x.id === state.selected.id);
          return domain ? state.data.servers.find(x => x.id === domain.serverId) || null : null;
        }
        if (state.selected.type === 'domainDraft') {
          const ip = state.data.ips.find(x => x.id === state.selected.id);
          return ip ? state.data.servers.find(x => x.id === ip.serverId) || null : null;
        }
        return null;
      }

      function getCurrentContextIp() {
        if (state.selected.type === 'ip') return state.data.ips.find(x => x.id === state.selected.id) || null;
        if (state.selected.type === 'domain') {
          const domain = state.data.domains.find(x => x.id === state.selected.id);
          return domain ? state.data.ips.find(x => x.id === domain.ipId) || null : null;
        }
        if (state.selected.type === 'domainDraft') return state.data.ips.find(x => x.id === state.selected.id) || null;
        return null;
      }

      function getDomainReadiness(domain) {
        const checks = [];
        const server = state.data.servers.find(s => s.id === domain.serverId);
        const ip = state.data.ips.find(i => i.id === domain.ipId);
        checks.push({ label: 'Server assigned', ok: !!server });
        checks.push({ label: 'IP assigned', ok: !!ip && isValidIPv4(ip.ip) });
        checks.push({ label: 'Domain valid', ok: isValidDomain(domain.domain) });
        checks.push({ label: 'VMTA exists', ok: !!domain.vmta?.trim() });
        checks.push({ label: 'HELO exists', ok: !!domain.helo?.trim() });
        checks.push({ label: 'PTR exists', ok: !!domain.ptr?.trim() });
        checks.push({ label: 'SPF valid', ok: /^v=spf1\s+/i.test(domain.spf || '') });
        checks.push({ label: 'DMARC valid', ok: /^v=DMARC1\s*;/i.test(domain.dmarc || '') });
        checks.push({ label: 'DKIM selector', ok: !!domain.selector?.trim() });
        checks.push({ label: 'DKIM path valid', ok: isValidPemPath(domain.domain, domain.pemPath) });
        checks.push({ label: 'Public key present', ok: !!domain.publicKey?.trim() });
        const okCount = checks.filter(c => c.ok).length;
        return { score: Math.round(okCount / checks.length * 100), checks };
      }

      function getDomainMissingChecks(domain) {
        return getDomainReadiness(domain).checks.filter(check => !check.ok);
      }

      function getDomainMissingBadge(domain) {
        const missingChecks = getDomainMissingChecks(domain);
        if (!missingChecks.length) return '';
        return statusBadge(`Missing ${missingChecks.length}`, 'err');
      }

      function getDraftMissingChecks(draft) {
        if (!draft) return [];
        const checks = [
          { label: 'Domain valid', ok: isValidDomain(draft.domain) },
          { label: 'VMTA exists', ok: !!draft.vmta?.trim() },
          { label: 'HELO exists', ok: !!draft.helo?.trim() },
          { label: 'PTR exists', ok: !!draft.ptr?.trim() },
          { label: 'SPF valid', ok: /^v=spf1\s+/i.test(draft.spf || '') },
          { label: 'DMARC valid', ok: /^v=DMARC1\s*;/i.test(draft.dmarc || '') },
          { label: 'DKIM selector', ok: !!draft.selector?.trim() },
          { label: 'DKIM path valid', ok: isValidPemPath(draft.domain, draft.pemPath) },
          { label: 'Public key present', ok: !!draft.publicKey?.trim() },
        ];
        return checks.filter(check => !check.ok);
      }

      function getIpMissingCount(ip, linkedDomains = null, draft = null) {
        const domains = linkedDomains || state.data.domains.filter(domain => domain.ipId === ip.id);
        const draftRecord = draft ?? state.data.domainDraftsByIp?.[ip.id] ?? null;
        const domainMissingCount = domains.reduce((total, domain) => total + getDomainMissingChecks(domain).length, 0);
        const draftMissingCount = domains.length ? 0 : getDraftMissingChecks(draftRecord).length;
        return domainMissingCount + draftMissingCount;
      }

      function getServerMissingCount(server, ips = null, domains = null) {
        const serverIps = ips || state.data.ips.filter(ip => ip.serverId === server.id);
        const serverDomains = domains || state.data.domains.filter(domain => domain.serverId === server.id);
        const domainMissingCount = serverDomains.reduce((total, domain) => total + getDomainMissingChecks(domain).length, 0);
        const draftMissingCount = serverIps.reduce((total, ip) => {
          const hasLinkedDomain = serverDomains.some(domain => domain.ipId === ip.id);
          if (hasLinkedDomain) return total;
          return total + getDraftMissingChecks(state.data.domainDraftsByIp?.[ip.id] || null).length;
        }, 0);
        return domainMissingCount + draftMissingCount;
      }

      function getCurrentSelectedServerId() {
        if (state.selected.type === 'server') return state.selected.id || null;
        if (state.selected.type === 'ip') return state.data.ips.find(x => x.id === state.selected.id)?.serverId || null;
        if (state.selected.type === 'domain') return state.data.domains.find(x => x.id === state.selected.id)?.serverId || null;
        return null;
      }

      function getServerConfigStatus(server) {
        if (!server) return { required: false, missing: false, synced: false, generatedConfig: '' };
        const generatedConfig = generatePmtaForServer(server.id) || '';
        if (!generatedConfig) return { required: false, missing: false, synced: false, generatedConfig: '' };
        const fingerprint = generatedConfig.trim();
        const synced = Boolean(server.pmtaConfigPolledAt && server.pmtaConfigFingerprint === fingerprint);
        return {
          required: true,
          missing: !synced,
          synced,
          generatedConfig,
          polledAt: server.pmtaConfigPolledAt || '',
          remotePath: server.pmtaConfigRemotePath || '',
        };
      }

      function statusBadge(text, cls = 'muted') {
        return `<span class="status ${cls}">${escapeHtml(text)}</span>`;
      }

      function statusBadgeByScore(score) {
        if (score >= 90) return statusBadge(`Ready ${score}%`, 'ok');
        if (score >= 60) return statusBadge(`Partial ${score}%`, 'warn');
        return statusBadge(`Issues ${score}%`, 'err');
      }

      function findLinkedServerNameForDomain(domainName) {
        const data = state.data || defaultData();
        const direct = data.domains.find(d => normalizeDomain(d.domain) === normalizeDomain(domainName));
        if (!direct) return '';
        const server = data.servers.find(s => s.id === direct.serverId);
        return server?.name || '';
      }

      function findLinkedIpsForDomain(domainName) {
        const data = state.data || defaultData();
        return data.domains
          .filter(d => normalizeDomain(d.domain) === normalizeDomain(domainName))
          .map(d => data.ips.find(ip => ip.id === d.ipId)?.ip || '')
          .filter(Boolean);
      }

      function populateRegistryFilters() {
        const providerSelect = document.getElementById('registryProviderFilter');
        const accountSelect = document.getElementById('registryAccountFilter');
        if (!providerSelect || !accountSelect) return;
        const providers = [...new Set(state.data.domainRegistry.map(x => (x.provider || '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
        const accounts = [...new Set(state.data.domainRegistry.map(x => (x.accountUser || '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
        const currentProvider = providerSelect.value;
        const currentAccount = accountSelect.value;
        providerSelect.innerHTML = `<option value="">All providers</option>` + providers.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
        accountSelect.innerHTML = `<option value="">All account users</option>` + accounts.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
        if (providers.includes(currentProvider)) providerSelect.value = currentProvider;
        if (accounts.includes(currentAccount)) accountSelect.value = currentAccount;
      }

      function getRegistryMetrics(filteredItems) {
        const linkedCount = filteredItems.filter(item => !!findLinkedServerNameForDomain(item.domain)).length;
        const expiredCount = filteredItems.filter(item => getServerExpiryStatus(item.expiryDate || '').cls === 'err' && getServerExpiryStatus(item.expiryDate || '').label === 'Expired').length;
        const providersCount = new Set(filteredItems.map(item => (item.provider || 'No provider').trim() || 'No provider')).size;
        return {
          total: filteredItems.length,
          linked: linkedCount,
          expired: expiredCount,
          providers: providersCount,
        };
      }

      function populateRegistryForm(item = null) {
        const set = (id, value) => {
          const el = document.getElementById(id);
          if (el) el.value = value || '';
        };
        set('registryDomainName', item?.domain || '');
        set('registryDomainProvider', item?.provider || '');
        set('registryDomainExpiryDate', item?.expiryDate || '');
        set('registryDomainAccountUser', item?.accountUser || '');
        set('registryDomainNote', item?.note || '');
      }

      function clearRegistryForm() {
        state.selectedRegistryDomainId = null;
        populateRegistryForm(null);
      }

      function renderDomainsRegistry() {
        const box = document.getElementById('domainsRegistryContent');
        const providerFilter = document.getElementById('registryProviderFilter')?.value || '';
        const accountFilter = document.getElementById('registryAccountFilter')?.value || '';
        if (!box) return;
        populateRegistryFilters();

        const filtered = state.data.domainRegistry.filter(item => {
          const providerOk = !providerFilter || (item.provider || '').trim() === providerFilter;
          const accountOk = !accountFilter || (item.accountUser || '').trim() === accountFilter;
          return providerOk && accountOk;
        });

        const metrics = getRegistryMetrics(filtered);
        const totalPages = Math.max(1, Math.ceil(filtered.length / state.registryPageSize));
        if (state.registryPage > totalPages) state.registryPage = totalPages;
        const startIndex = (state.registryPage - 1) * state.registryPageSize;
        const paged = filtered.slice(startIndex, startIndex + state.registryPageSize);

        if (!filtered.length) {
          box.className = 'notice';
          box.innerHTML = 'No registry domains match the selected filters.';
          return;
        }

        const grouped = new Map();
        paged.forEach(item => {
          const providerKey = (item.provider || 'No provider').trim() || 'No provider';
          const accountKey = (item.accountUser || 'No account user').trim() || 'No account user';
          const groupKey = `${providerKey}__${accountKey}`;
          if (!grouped.has(groupKey)) grouped.set(groupKey, { provider: providerKey, account: accountKey, items: [] });
          grouped.get(groupKey).items.push(item);
        });

        box.className = '';
        box.innerHTML = `
          <div class="registry-monitor">
            <div class="registry-stat"><div class="label">Filtered Domains</div><div class="value">${metrics.total}</div></div>
            <div class="registry-stat"><div class="label">Linked Domains</div><div class="value">${metrics.linked}</div></div>
            <div class="registry-stat"><div class="label">Expired</div><div class="value">${metrics.expired}</div></div>
            <div class="registry-stat"><div class="label">Providers</div><div class="value">${metrics.providers}</div></div>
          </div>
          <div class="pagination-bar">
            <div class="pagination-info">Page ${state.registryPage} of ${totalPages} · Showing ${paged.length} of ${filtered.length} filtered domains</div>
            <div class="pagination-actions">
              <button id="registryPrevPageBtn" ${state.registryPage <= 1 ? 'disabled' : ''}>Previous</button>
              <button id="registryNextPageBtn" ${state.registryPage >= totalPages ? 'disabled' : ''}>Next</button>
            </div>
          </div>
          <div class="domain-list-compact">
            ${Array.from(grouped.values()).map(group => `
              <div class="group-block">
                <div class="group-title">${escapeHtml(group.provider)}</div>
                <div class="group-subtitle">Account User: ${escapeHtml(group.account)}</div>
                <div class="domain-list-compact">
                  ${group.items.map(item => {
                    const linkedServerName = findLinkedServerNameForDomain(item.domain);
                    const linkedIps = findLinkedIpsForDomain(item.domain);
                    const expiryStatus = getServerExpiryStatus(item.expiryDate || '');
                    const isSelected = state.selectedRegistryDomainId === item.id;
                    return `
                      <div class="domain-row ${isSelected ? 'active' : ''}">
                        <div class="domain-row-top">
                          <strong class="ltr">${escapeHtml(item.domain)}</strong>
                          <div class="domain-actions">
                            ${statusBadge(expiryStatus.label, expiryStatus.cls)}
                            <button class="btn-sm" data-registry-action="edit" data-registry-id="${item.id}">Edit</button>
                            <button class="btn-sm btn-danger" data-registry-action="delete" data-registry-id="${item.id}">Delete</button>
                          </div>
                        </div>
                        <div class="tree-leaf-meta break-safe">Provider: ${escapeHtml(item.provider || '-')} · Account: ${escapeHtml(item.accountUser || '-')}</div>
                        <div class="tree-leaf-meta break-safe">Expiry: ${escapeHtml(item.expiryDate || '-')} · Linked Server: ${escapeHtml(linkedServerName || '-')}</div>
                        <div class="tree-leaf-meta break-safe">Linked IPs:</div>
                        <div class="linked-ip-list">${linkedIps.length ? linkedIps.map(ip => statusBadge(ip, 'muted')).join('') : statusBadge('Not linked', 'muted')}</div>
                        <div class="tree-leaf-meta break-safe clamp-note">Note: ${escapeHtml(item.note || '-')}</div>
                      </div>
                    `;
                  }).join('')}
                </div>
              </div>
            `).join('')}
          </div>
        `;
      }

      function calcStats() {
        const { servers, ips, domains } = state.data || defaultData();
        let ready = 0, partial = 0, broken = 0;
        domains.forEach(d => {
          const r = getDomainReadiness(d);
          if (r.score >= 90) ready++;
          else if (r.score >= 60) partial++;
          else broken++;
        });
        return [
          { label: 'Servers', value: servers.length },
          { label: 'Additional IPs', value: ips.length },
          { label: 'Domains', value: domains.length },
          { label: 'Ready / Partial / Broken', value: `${ready} / ${partial} / ${broken}` },
        ];
      }

      function renderStats() {
        const wrap = document.getElementById('stats');
        if (!wrap) return;
        wrap.innerHTML = calcStats().map(s => `
          <div class="stat">
            <div class="label">${escapeHtml(s.label)}</div>
            <div class="value">${escapeHtml(String(s.value))}</div>
          </div>
        `).join('');
      }

      function buildWorkspaceNav(active = 'server', contextServer = null) {
        const serverLabel = contextServer ? ` · ${escapeHtml(contextServer.name)}` : '';
        const hasDomainContext = !!getCurrentContextIp();
        return `
          <div class="workspace-nav">
            <button class="workspace-nav-btn ${active === 'server' ? 'active' : ''}" id="openServerWorkspaceBtn">Server${serverLabel}</button>
            <button class="workspace-nav-btn ${active === 'ip' ? 'active' : ''}" id="openIpWorkspaceBtn">IP</button>
            ${hasDomainContext ? `<button class="workspace-nav-btn ${active === 'domain' ? 'active' : ''}" id="openDomainWorkspaceBtn">Domain</button>` : ''}
          </div>
        `;
      }

      function getServerExpiryStatus(expiryDate) {
        if (!expiryDate) return { label: 'No expiry', cls: 'muted' };
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const expiry = new Date(expiryDate);
        if (Number.isNaN(expiry.getTime())) return { label: 'Invalid expiry', cls: 'err' };
        expiry.setHours(0, 0, 0, 0);
        const diffDays = Math.ceil((expiry - today) / 86400000);
        if (diffDays < 0) return { label: 'Expired', cls: 'err' };
        if (diffDays <= 7) return { label: `Expires in ${diffDays}d`, cls: 'err' };
        if (diffDays <= 30) return { label: `Expires in ${diffDays}d`, cls: 'warn' };
        return { label: `Expires in ${diffDays}d`, cls: 'ok' };
      }

      function buildServerForm(server = null) {
        const expiryStatus = getServerExpiryStatus(server?.expiryDate || '');
        const ssh = getServerSshSettings(server);
        return `
          ${buildWorkspaceNav('server', server)}
          <div class="notice">Create a server root node. The SSH section is now embedded here because DKIM generation depends on the selected server connection.</div>
          <div class="divider"></div>
          <h4>SSH / DKIM Settings</h4>
          <div class="sub">These settings are reused by the Bulk DKIM generator and by the automatic single-domain DKIM generation triggered from PTR.</div>
          <div class="row">
            <div>
              <label>SSH Host</label>
              <input id="serverSshHost" placeholder="server.example.com" value="${escapeHtml(ssh.sshHost)}" />
            </div>
            <div>
              <label>SSH Port</label>
              <input id="serverSshPort" type="number" placeholder="22" value="${escapeHtml(ssh.sshPort)}" />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>SSH Timeout (sec)</label>
              <input id="serverSshTimeout" type="number" placeholder="20" value="${escapeHtml(ssh.sshTimeout)}" />
            </div>
            <div>
              <label>SSH Username</label>
              <input id="serverSshUser" placeholder="root" value="${escapeHtml(ssh.sshUser)}" />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>SSH Password</label>
              <input id="serverSshPass" type="password" value="${escapeHtml(ssh.sshPass)}" />
            </div>
            <div>
              <label>DKIM filename</label>
              <input id="serverDkimFilename" value="${escapeHtml(ssh.dkimFilename)}" />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>Key size</label>
              <select id="serverKeySize">
                <option value="2048" ${ssh.keySize === '2048' ? 'selected' : ''}>2048 (recommended)</option>
                <option value="1024" ${ssh.keySize === '1024' ? 'selected' : ''}>1024 (legacy)</option>
                <option value="4096" ${ssh.keySize === '4096' ? 'selected' : ''}>4096</option>
              </select>
            </div>
            <div>
              <label>SSH Connection Check</label>
              <div class="inline-actions">
                <button id="serverCheckSshBtn" type="button">Check SSH Connection</button>
                <span id="serverSshStatus" class="status muted">Not checked</span>
              </div>
            </div>
          </div>
          <div class="divider"></div>
          <h4>Server Details</h4>
          <div class="row">
            <div>
              <label>Server Name</label>
              <input id="serverName" placeholder="Example: srv-fr-01" value="${escapeHtml(server?.name || '')}" />
            </div>
            <div>
              <label>Provider / Location</label>
              <input id="serverProvider" placeholder="OVH / Hetzner / France" value="${escapeHtml(server?.provider || '')}" />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>Server Expiry Date</label>
              <input id="serverExpiryDate" type="date" value="${escapeHtml(server?.expiryDate || '')}" />
              <div style="margin-top:8px;">${statusBadge(expiryStatus.label, expiryStatus.cls)}</div>
            </div>
            <div>
              <label>Provider Account User</label>
              <input id="serverAccountUser" placeholder="account@example.com or provider username" value="${escapeHtml(server?.accountUser || '')}" />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>Server Notes</label>
              <textarea id="serverNotes" placeholder="Any note related to this server">${escapeHtml(server?.notes || '')}</textarea>
            </div>
          </div>
          <div style="margin-top:12px;">
            <button id="addServerBtn" class="btn-primary">${server ? 'Save Server' : 'Add Server'}</button>
          </div>
        `;
      }

      function buildIpForm(ip = null, contextServer = null) {
        const effectiveServer = contextServer || (ip ? state.data.servers.find(server => server.id === ip.serverId) || null : null);
        const lockedServerId = effectiveServer?.id || '';
        return `
          ${buildWorkspaceNav('ip', effectiveServer)}
          <div class="notice">Add an IP under the selected server. If Internal IP Label is empty, it is generated automatically. While typing PTR, HELO mirrors it automatically.</div>
          <div class="divider"></div>
          <div>
            <label>Selected Server</label>
            <input id="ipServerName" class="readonly" value="${escapeHtml(effectiveServer?.name || 'No server selected')}" readonly />
            <input id="ipServerSelect" type="hidden" value="${escapeHtml(lockedServerId)}" />
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>Additional IP</label>
              <input id="ipAddress" placeholder="194.116.172.135" value="${escapeHtml(ip?.ip || '')}" />
            </div>
            <div>
              <label>Internal IP Label</label>
              <input id="ipLabel" placeholder="Auto: ip-mail-01" value="${escapeHtml(ip?.label || '')}" />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>PTR / Reverse DNS</label>
              <input id="ipPtr" placeholder="mail.example.com" value="${escapeHtml(ip?.ptr || '')}" />
            </div>
            <div>
              <label>Default HELO</label>
              <input id="ipHelo" class="readonly" placeholder="Auto-filled from PTR" value="${escapeHtml(ip?.helo || '')}" readonly />
            </div>
          </div>
          <div style="margin-top:12px;">
            <button id="addIpBtn" class="btn-primary">${ip ? 'Save IP' : 'Add IP'}</button>
          </div>
        `;
      }

      function buildDomainForm(domain = null, preferredIpId = '', contextServer = null) {
        const selectedIpId = domain?.ipId || preferredIpId || '';
        const preferredIp = selectedIpId ? state.data.ips.find(ip => ip.id === selectedIpId) || null : null;
        const effectiveServer = contextServer || (domain ? state.data.servers.find(server => server.id === domain.serverId) || null : preferredIp ? state.data.servers.find(server => server.id === preferredIp.serverId) || null : null);
        const effectiveIp = domain ? state.data.ips.find(ip => ip.id === domain.ipId) || null : preferredIp;
        return `
          ${buildWorkspaceNav('domain', effectiveServer)}
          <div class="notice">This domain workspace is scoped automatically from the infrastructure tree. DKIM now generates automatically from PTR using the selected server SSH settings, and you can regenerate it here if needed. Use Polling NameChip to sync A, MX, SPF, DKIM, and DMARC records into Namecheap.</div>
          <div class="divider"></div>
          <div class="small muted">Context: ${escapeHtml(effectiveServer?.name || 'No server')} → ${escapeHtml(effectiveIp?.ip || 'No IP selected')} → Domain Workspace</div>
          <input id="domainServerSelect" type="hidden" value="${escapeHtml(effectiveServer?.id || '')}" />
          <input id="domainIpSelect" type="hidden" value="${escapeHtml(effectiveIp?.id || '')}" />
          <div id="domainIpHelp" class="small muted" style="margin-top:8px;">${effectiveIp ? `Using IP context: ${escapeHtml(effectiveIp.ip)}` : 'No direct IP context detected.'}</div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>Domain</label>
              <input id="domainName" class="readonly" placeholder="Auto-generated from selected IP PTR" value="${escapeHtml(domain?.domain || '')}" readonly />
            </div>
            <div>
              <label>Virtual MTA Name</label>
              <input id="domainVmta" class="readonly" placeholder="Auto-generated from domain" value="${escapeHtml(domain?.vmta || '')}" readonly />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>HELO</label>
              <input id="domainHelo" class="readonly" placeholder="Auto-filled from selected IP PTR / HELO" value="${escapeHtml(domain?.helo || '')}" readonly />
            </div>
            <div>
              <label>DKIM Selector</label>
              <input id="domainSelector" class="readonly" value="${escapeHtml(domain?.selector || 'dkim')}" readonly />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>DKIM PEM Path</label>
              <input id="domainPemPath" class="readonly" placeholder="/root/example.com/dkim.pem" value="${escapeHtml(domain?.pemPath || '')}" readonly />
            </div>
            <div>
              <label>DMARC Policy</label>
              <input id="domainDmarc" class="readonly" placeholder="Auto-generated from domain" value="${escapeHtml(domain?.dmarc || '')}" readonly />
            </div>
          </div>
          <div class="row" style="margin-top:12px;">
            <div>
              <label>SPF</label>
              <input id="domainSpf" class="readonly" placeholder="Auto-generated from selected IP" value="${escapeHtml(domain?.spf || '')}" readonly />
            </div>
            <div>
              <label>PTR / Reverse DNS</label>
              <input id="domainPtr" class="readonly" placeholder="Auto-filled from selected IP PTR" value="${escapeHtml(domain?.ptr || '')}" readonly />
            </div>
          </div>
          <div style="margin-top:12px;">
            <label>DKIM Public Key</label>
            <textarea id="domainPublicKey" placeholder="Generated DKIM public key will appear here">${escapeHtml(domain?.publicKey || '')}</textarea>
          </div>
          <div id="domainMissingNotice" class="notice ${domain?.publicKey ? 'ok' : 'warn'}" style="margin-top:12px;">
            ${domain?.publicKey
              ? 'DKIM public key is present. This domain can be saved without a missing-status warning for DKIM.'
              : 'Warning: DKIM Public Key is empty. If you do not click "Generate DKIM From PTR Domain", this domain will be saved as Missing in the server tree, IP node, and domain node.'}
          </div>
          <div class="inline-actions" style="margin-top:12px;">
            <button id="generateDomainDkimBtn" type="button">Generate DKIM From PTR Domain</button>
            <button id="pollNamecheapBtn" type="button" class="btn-warning">Polling NameChip</button>
          </div>
          <div style="margin-top:12px;">
            <button id="addDomainBtn" class="btn-primary">${domain ? 'Save Domain' : 'Add Domain'}</button>
          </div>
        `;
      }

      function renderInfraTree() {
        const tree = document.getElementById('infraTree');
        if (!tree) return;
        if (!state.data.servers.length) {
          tree.innerHTML = `<div class="notice">No servers yet. Add your first server to start building the tree.</div>`;
          return;
        }

        tree.innerHTML = state.data.servers.map(server => {
          const ips = state.data.ips.filter(ip => ip.serverId === server.id);
          const domains = state.data.domains.filter(d => d.serverId === server.id);
          const serverActive = state.selected.type === 'server' && state.selected.id === server.id ? 'active' : '';
          const serverExpanded = !state.treeCollapsed && !!state.expandedServers[server.id];
          const expiryStatus = getServerExpiryStatus(server.expiryDate || '');
          const serverMissingCount = getServerMissingCount(server, ips, domains);
          const serverConfigStatus = getServerConfigStatus(server);
          return `
            <div class="tree-node ${serverActive}">
              <div class="tree-node-header" data-select-type="server" data-select-id="${server.id}">
                <div>
                  <div class="tree-node-title">${escapeHtml(server.name)}</div>
                  <div class="tree-node-sub">${escapeHtml(server.provider || 'No provider')}${server.accountUser ? ' · ' + escapeHtml(server.accountUser) : ''}${server.expiryDate ? ' · ' + escapeHtml(server.expiryDate) : ''}</div>
                </div>
                <div>
                  <span class="status muted" data-server-toggle="ips" data-server-id="${server.id}">${ips.length} IPs</span>
                  <span class="status muted" data-server-toggle="domains" data-server-id="${server.id}" style="margin-left:6px;">${domains.length} Domains</span>
                  ${serverConfigStatus.missing ? statusBadge('Config', 'err') : ''}
                  ${serverMissingCount ? statusBadge(`Missing ${serverMissingCount}`, 'err') : ''}
                  ${statusBadge(expiryStatus.label, expiryStatus.cls)}
                  <span class="status delete" data-delete-type="server" data-delete-id="${server.id}" style="margin-left:6px;">Delete</span>
                </div>
              </div>
              <div class="tree-node-children ${serverExpanded ? '' : 'hidden'}">
                ${ips.length ? ips.map(ip => {
                  const ipDomains = state.data.domains.filter(d => d.ipId === ip.id);
                  const draft = state.data.domainDraftsByIp?.[ip.id];
                  const ipActive = state.selected.type === 'ip' && state.selected.id === ip.id ? 'active' : '';
                  const ipExpanded = !!state.expandedIps[ip.id];
                  const ipMissingCount = getIpMissingCount(ip, ipDomains, draft);
                  return `
                    <div class="tree-leaf ${ipActive}" data-select-type="ip" data-select-id="${ip.id}">
                      <div class="tree-leaf-head">
                        <div class="tree-leaf-title ltr">${escapeHtml(ip.ip)}</div>
                        <div>
                          ${statusBadge(ip.label || 'No label', 'muted')}
                          <span class="status muted" data-ip-toggle="domains" data-ip-id="${ip.id}" style="margin-left:6px;">${ipDomains.length || (draft ? 1 : 0)} Domains</span>
                          ${ipMissingCount ? statusBadge(`Missing ${ipMissingCount}`, 'err') : ''}
                          <span class="status delete" data-delete-type="ip" data-delete-id="${ip.id}" style="margin-left:6px;">Delete</span>
                        </div>
                      </div>
                      <div class="tree-leaf-meta">PTR: <span class="ltr">${escapeHtml(ip.ptr || '-')}</span> · HELO: <span class="ltr">${escapeHtml(ip.helo || '-')}</span></div>
                      <div class="tree-indent ${ipExpanded ? '' : 'hidden'}" style="margin-top:8px;">
                        ${ipDomains.length ? ipDomains.map(domain => {
                          const readiness = getDomainReadiness(domain);
                          const active = state.selected.type === 'domain' && state.selected.id === domain.id ? 'active' : '';
                          const domainMissingBadge = getDomainMissingBadge(domain);
                          return `
                            <div class="tree-leaf ${active}" data-select-type="domain" data-select-id="${domain.id}">
                              <div class="tree-leaf-head">
                                <div class="tree-leaf-title ltr">${escapeHtml(domain.domain)}</div>
                                <div>
                                  ${domainMissingBadge || statusBadgeByScore(readiness.score)}
                                  <span class="status delete" data-delete-type="domain" data-delete-id="${domain.id}" style="margin-left:6px;">Delete</span>
                                </div>
                              </div>
                              <div class="tree-leaf-meta ltr">${escapeHtml(domain.vmta || '-')} · ${escapeHtml(domain.helo || '-')}</div>
                            </div>
                          `;
                        }).join('') : draft ? `
                          <div class="tree-leaf" data-open-domain-draft="${ip.id}">
                            <div class="tree-leaf-head">
                              <div class="tree-leaf-title ltr">${escapeHtml(draft.domain)}</div>
                              <div>${getDraftMissingChecks(draft).length ? statusBadge(`Missing ${getDraftMissingChecks(draft).length}`, 'err') : statusBadge('Draft', 'warn')}</div>
                            </div>
                            <div class="tree-leaf-meta">Ready for domain completion. Review the generated DKIM public key in the workspace, then save.</div>
                          </div>
                        ` : `<div class="tree-leaf"><div class="tree-leaf-meta">No domain linked to this IP yet.</div></div>`}
                      </div>
                    </div>
                  `;
                }).join('') : `<div class="tree-leaf"><div class="tree-leaf-meta">No IPs assigned to this server yet.</div></div>`}
              </div>
            </div>
          `;
        }).join('');
      }

      function syncQuickManagementLayout() {
        const qmLayout = document.getElementById('qmLayout');
        const treeShell = document.getElementById('treeShell');
        const workspaceShell = document.getElementById('workspaceShell');
        if (!qmLayout || !treeShell || !workspaceShell) return;
        if (state.showWorkspace) {
          qmLayout.classList.add('with-workspace');
          treeShell.classList.remove('full-width');
          workspaceShell.classList.remove('hidden-panel');
        } else {
          qmLayout.classList.remove('with-workspace');
          treeShell.classList.add('full-width');
          workspaceShell.classList.add('hidden-panel');
        }
      }

      function renderWorkspace() {
        const title = document.getElementById('workspaceTitle');
        const badge = document.getElementById('workspaceBadge');
        const content = document.getElementById('workspaceContent');
        if (!title || !badge || !content) return;

        syncQuickManagementLayout();

        if (!state.showWorkspace) {
          title.textContent = 'Server Workspace';
          badge.className = 'status muted';
          badge.textContent = 'Hidden';
          content.innerHTML = '';
          return;
        }

        if (state.workspaceMode === 'ip') {
          const selectedIp = state.selected.type === 'ip' ? state.data.ips.find(x => x.id === state.selected.id) || null : null;
          const contextServer = getCurrentContextServer();
          title.textContent = `${contextServer?.name || 'Server'} → IP Workspace`;
          badge.className = 'status warn';
          badge.textContent = 'Scoped IP form';
          content.innerHTML = buildIpForm(selectedIp, contextServer);
          return;
        }

        if (state.workspaceMode === 'domain') {
          const contextIp = getCurrentContextIp();
          const contextServer = getCurrentContextServer();
          if (!contextIp) {
            title.textContent = `${contextServer?.name || 'Server'} → Domain Workspace`;
            badge.className = 'status err';
            badge.textContent = 'IP required';
            content.innerHTML = `${buildWorkspaceNav('server', contextServer)}<div class="notice err">Domain Workspace requires an IP context. Add an IP first or select an existing IP or domain from the infrastructure tree.</div>`;
            return;
          }
          const selectedDomain = state.selected.type === 'domain' ? state.data.domains.find(x => x.id === state.selected.id) || null : null;
          title.textContent = `${contextServer?.name || 'Server'} → Domain Workspace`;
          badge.className = 'status warn';
          badge.textContent = 'Scoped domain form';
          content.innerHTML = buildDomainForm(selectedDomain, contextIp.id, contextServer);
          hydrateDomainAutoFields();
          if (!selectedDomain) autoFillDomainFieldsFromSelectedIp();
          updateDomainMissingNotice();
          return;
        }

        if (!state.selected.type || !state.selected.id) {
          title.textContent = 'Server Workspace';
          badge.className = 'status muted';
          badge.textContent = 'No selection';
          content.innerHTML = buildServerForm();
          return;
        }

        if (state.selected.type === 'server') {
          const server = state.data.servers.find(x => x.id === state.selected.id) || null;
          title.textContent = `${server?.name || 'Server'} → Server Workspace`;
          badge.className = 'status ok';
          badge.textContent = 'Server selected';
          content.innerHTML = buildServerForm(server);
          return;
        }

        if (state.selected.type === 'ip') {
          const ip = state.data.ips.find(x => x.id === state.selected.id) || null;
          const contextServer = getCurrentContextServer();
          title.textContent = `${contextServer?.name || 'Server'} → IP Workspace`;
          badge.className = 'status ok';
          badge.textContent = 'IP selected';
          content.innerHTML = buildIpForm(ip, contextServer);
          return;
        }

        if (state.selected.type === 'domain') {
          const domain = state.data.domains.find(x => x.id === state.selected.id) || null;
          const contextServer = getCurrentContextServer();
          title.textContent = `${contextServer?.name || 'Server'} → Domain Workspace`;
          badge.className = 'status ok';
          badge.textContent = 'Domain selected';
          content.innerHTML = buildDomainForm(domain, domain?.ipId || '', contextServer);
          hydrateDomainAutoFields();
          updateDomainMissingNotice();
          return;
        }
      }

      function renderOverview() {
        const hero = document.getElementById('overviewHero');
        const hierarchy = document.getElementById('overviewHierarchy');
        const domainsBox = document.getElementById('overviewDomains');
        const health = document.getElementById('overviewHealth');
        const config = document.getElementById('overviewConfig');
        if (!hero || !hierarchy || !domainsBox || !health || !config) return;

        if (!state.selected.type || !state.selected.id) {
          hero.innerHTML = `<h4>Selection Summary</h4><div class="muted-box">Select a server, IP, or domain from the infrastructure tree to populate this overview.</div>`;
          hierarchy.innerHTML = `<h4>Hierarchy</h4><div class="muted-box">The hierarchy path will appear here.</div>`;
          domainsBox.innerHTML = `<h4>Linked Domains</h4><div class="muted-box">No linked domains to display yet.</div>`;
          health.innerHTML = `<h4>Health & Readiness</h4><div class="muted-box">Readiness and quick checks will appear here.</div>`;
          config.innerHTML = `<h4>Config Snapshot</h4><div class="muted-box">Core sending configuration will appear here.</div>`;
          return;
        }

        if (state.selected.type === 'server') {
          const server = state.data.servers.find(x => x.id === state.selected.id);
          const ips = state.data.ips.filter(x => x.serverId === server.id);
          const domains = state.data.domains.filter(x => x.serverId === server.id);
          hero.innerHTML = `
            <h4>Selection Summary</h4>
            <div class="kv">
              <div class="kv-row"><span>Name</span><strong>${escapeHtml(server.name)}</strong></div>
              <div class="kv-row"><span>Provider</span><strong>${escapeHtml(server.provider || '-')}</strong></div>
              <div class="kv-row"><span>Expiry Date</span><strong>${escapeHtml(server.expiryDate || '-')}</strong></div>
              <div class="kv-row"><span>Account User</span><strong>${escapeHtml(server.accountUser || '-')}</strong></div>
              <div class="kv-row"><span>Notes</span><strong>${escapeHtml(server.notes || '-')}</strong></div>
            </div>`;
          hierarchy.innerHTML = `<h4>Hierarchy</h4><div class="muted-box">Server <strong>${escapeHtml(server.name)}</strong> is the root node. It currently owns ${ips.length} IPs and ${domains.length} linked domains.</div>`;
          domainsBox.innerHTML = `<h4>Linked Domains</h4>${domains.length ? `<div class="domain-list-compact">${domains.map(d => `<div class="domain-row"><div class="domain-row-top"><strong class="ltr">${escapeHtml(d.domain)}</strong>${statusBadgeByScore(getDomainReadiness(d).score)}</div><div class="tree-leaf-meta ltr">${escapeHtml(d.vmta || '-')} · ${escapeHtml(d.helo || '-')}</div></div>`).join('')}</div>` : `<div class="muted-box">No domains linked to this server yet.</div>`}`;
          health.innerHTML = `
            <h4>Health & Readiness</h4>
            <div class="kv">
              <div class="kv-row"><span>IPs</span><strong>${ips.length}</strong></div>
              <div class="kv-row"><span>Domains</span><strong>${domains.length}</strong></div>
              <div class="kv-row"><span>Domain drafts</span><strong>${Object.values(state.data.domainDraftsByIp || {}).filter(d => d.serverId === server.id).length}</strong></div>
            </div>`;
          const configStatus = getServerConfigStatus(server);
          config.innerHTML = `<h4>Config Snapshot</h4><div class="muted-box">Use PowerMTA Config Studio to compare parsed config rows against this server and detect IP, VMTA, HELO, and DKIM path mismatches.${configStatus.required ? `<br><br><strong>Polling status:</strong> ${configStatus.missing ? '<span style="color:#ff9d9d">Config missing in server</span>' : '<span style="color:#7ff0bb">Config synced in server</span>'}${configStatus.polledAt ? ` · Last poll: ${escapeHtml(new Date(configStatus.polledAt).toLocaleString())}` : ''}` : '<br><br>This server does not yet have a full 5-domain PowerMTA config ready for polling.'}</div>`;
          return;
        }

        if (state.selected.type === 'ip') {
          const ip = state.data.ips.find(x => x.id === state.selected.id);
          const server = state.data.servers.find(x => x.id === ip.serverId);
          const domains = state.data.domains.filter(x => x.ipId === ip.id);
          const draft = state.data.domainDraftsByIp?.[ip.id];
          hero.innerHTML = `
            <h4>Selection Summary</h4>
            <div class="kv">
              <div class="kv-row"><span>Server</span><strong>${escapeHtml(server?.name || '-')}</strong></div>
              <div class="kv-row"><span>IP</span><strong class="ltr">${escapeHtml(ip.ip)}</strong></div>
              <div class="kv-row"><span>Internal Label</span><strong>${escapeHtml(ip.label || '-')}</strong></div>
              <div class="kv-row"><span>PTR</span><strong class="ltr">${escapeHtml(ip.ptr || '-')}</strong></div>
              <div class="kv-row"><span>HELO</span><strong class="ltr">${escapeHtml(ip.helo || '-')}</strong></div>
            </div>`;
          hierarchy.innerHTML = `<h4>Hierarchy</h4><div class="muted-box">Server <strong>${escapeHtml(server?.name || '-')}</strong> → IP <strong class="ltr">${escapeHtml(ip.ip)}</strong>${draft ? ` → Draft domain <strong class="ltr">${escapeHtml(draft.domain)}</strong>` : ''}</div>`;
          domainsBox.innerHTML = `<h4>Linked Domains</h4>${domains.length ? `<div class="domain-list-compact">${domains.map(d => `<div class="domain-row"><div class="domain-row-top"><strong class="ltr">${escapeHtml(d.domain)}</strong>${statusBadgeByScore(getDomainReadiness(d).score)}</div><div class="tree-leaf-meta ltr">${escapeHtml(d.vmta || '-')}</div></div>`).join('')}</div>` : draft ? `<div class="muted-box">A draft domain is prepared for this IP: <strong class="ltr">${escapeHtml(draft.domain)}</strong>. Open the domain workspace, review the generated DKIM public key, then save.</div>` : `<div class="muted-box">No domain linked to this IP yet.</div>`}`;
          health.innerHTML = `
            <h4>Health & Readiness</h4>
            <div class="kv">
              <div class="kv-row"><span>IPv4 valid</span><strong>${isValidIPv4(ip.ip) ? 'Yes' : 'No'}</strong></div>
              <div class="kv-row"><span>PTR present</span><strong>${ip.ptr ? 'Yes' : 'No'}</strong></div>
              <div class="kv-row"><span>HELO present</span><strong>${ip.helo ? 'Yes' : 'No'}</strong></div>
              <div class="kv-row"><span>Linked domains</span><strong>${domains.length}</strong></div>
            </div>`;
          config.innerHTML = `<h4>Config Snapshot</h4><div class="muted-box">Expected VMTA flow is generated from the extracted domain of this PTR. The draft uses SPF, DMARC, DKIM path, and VMTA naming automatically.</div>`;
          return;
        }

        if (state.selected.type === 'domain') {
          const domain = state.data.domains.find(x => x.id === state.selected.id);
          const server = state.data.servers.find(x => x.id === domain.serverId);
          const ip = state.data.ips.find(x => x.id === domain.ipId);
          const readiness = getDomainReadiness(domain);
          hero.innerHTML = `
            <h4>Selection Summary</h4>
            <div class="kv">
              <div class="kv-row"><span>Server</span><strong>${escapeHtml(server?.name || '-')}</strong></div>
              <div class="kv-row"><span>Domain</span><strong class="ltr">${escapeHtml(domain.domain)}</strong></div>
              <div class="kv-row"><span>IP</span><strong class="ltr">${escapeHtml(ip?.ip || '-')}</strong></div>
              <div class="kv-row"><span>VMTA</span><strong class="ltr">${escapeHtml(domain.vmta || '-')}</strong></div>
              <div class="kv-row"><span>HELO</span><strong class="ltr">${escapeHtml(domain.helo || '-')}</strong></div>
            </div>`;
          hierarchy.innerHTML = `<h4>Hierarchy</h4><div class="muted-box">Server <strong>${escapeHtml(server?.name || '-')}</strong> → IP <strong class="ltr">${escapeHtml(ip?.ip || '-')}</strong> → Domain <strong class="ltr">${escapeHtml(domain.domain)}</strong></div>`;
          domainsBox.innerHTML = `<h4>Linked Domains</h4><div class="domain-list-compact"><div class="domain-row"><div class="domain-row-top"><strong class="ltr">${escapeHtml(domain.domain)}</strong>${statusBadgeByScore(readiness.score)}</div><div class="tree-leaf-meta ltr">PTR ${escapeHtml(domain.ptr || '-')} · Selector ${escapeHtml(domain.selector || '-')}</div></div></div>`;
          health.innerHTML = `<h4>Health & Readiness</h4><div class="checklist">${readiness.checks.map(c => `<div class="check"><span>${escapeHtml(c.label)}</span><span>${c.ok ? statusBadge('OK', 'ok') : statusBadge('Fix', 'err')}</span></div>`).join('')}</div>`;
          config.innerHTML = `
            <h4>Config Snapshot</h4>
            <div class="kv">
              <div class="kv-row"><span>SPF</span><strong class="ltr">${escapeHtml(domain.spf || '-')}</strong></div>
              <div class="kv-row"><span>DMARC</span><strong class="ltr">${escapeHtml(domain.dmarc || '-')}</strong></div>
              <div class="kv-row"><span>DKIM Path</span><strong class="ltr">${escapeHtml(domain.pemPath || '-')}</strong></div>
              <div class="kv-row"><span>Public Key</span><strong>${domain.publicKey ? 'Present' : 'Missing'}</strong></div>
            </div>`;
        }
      }

      function renderDnsSummary(domain) {
        const box = document.getElementById('dnsContent');
        if (!box) return;
        if (!domain) {
          box.className = 'notice';
          box.innerHTML = 'Select a domain to view SPF / DKIM / DMARC / PTR / HELO details.';
          return;
        }
        const ip = state.data.ips.find(i => i.id === domain.ipId);
        const dkimHost = `${domain.selector}._domainkey.${domain.domain}`;
        box.className = 'notice';
        box.innerHTML = `
          <div><strong>Domain:</strong> <span class="ltr">${escapeHtml(domain.domain)}</span></div>
          <div><strong>IP:</strong> <span class="ltr">${escapeHtml(ip?.ip || '-')}</span></div>
          <div><strong>HELO / A:</strong> <span class="ltr">${escapeHtml(domain.helo || '-')}</span></div>
          <div><strong>PTR:</strong> <span class="ltr">${escapeHtml(domain.ptr || '-')}</span></div>
          <div><strong>SPF TXT:</strong> <div class="ltr">${escapeHtml(domain.spf || '-')}</div></div>
          <div style="margin-top:8px"><strong>DKIM Host:</strong> <span class="ltr">${escapeHtml(dkimHost)}</span></div>
          <div><strong>DKIM PEM Path:</strong> <span class="ltr">${escapeHtml(domain.pemPath || '-')}</span></div>
          <div><strong>DKIM Public Key:</strong> <div class="ltr">${escapeHtml(domain.publicKey || '-')}</div></div>
          <div style="margin-top:8px"><strong>DMARC TXT:</strong> <div class="ltr">${escapeHtml(domain.dmarc || '-')}</div></div>
        `;
      }

      function renderReadiness(domain) {
        const box = document.getElementById('readinessContent');
        if (!box) return;
        if (!domain) {
          box.className = 'notice';
          box.innerHTML = 'Select a domain or apply a config to view readiness.';
          return;
        }
        const rd = getDomainReadiness(domain);
        box.className = rd.score >= 90 ? 'notice ok' : rd.score >= 60 ? 'notice warn' : 'notice err';
        box.innerHTML = `
          <div><strong>Domain:</strong> <span class="ltr">${escapeHtml(domain.domain)}</span></div>
          <div style="margin-top:6px"><strong>Final Score:</strong> ${statusBadgeByScore(rd.score)}</div>
          <div class="divider"></div>
          <div class="checklist">
            ${rd.checks.map(c => `
              <div class="check">
                <span>${escapeHtml(c.label)}</span>
                <span>${c.ok ? statusBadge('Ready', 'ok') : statusBadge('Needs Fix', 'err')}</span>
              </div>
            `).join('')}
          </div>
        `;
      }

      function renderPmtaResults() {
        const body = document.getElementById('pmtaTableBody');
        const notices = document.getElementById('pmtaNotices');
        const diffs = document.getElementById('pmtaDiffs');
        if (!body || !notices || !diffs) return;
        if (!state.pmtaParsed) {
          body.innerHTML = '';
          notices.className = 'notice';
          notices.innerHTML = 'Paste a config and click Parse.';
          diffs.className = 'notice';
          diffs.innerHTML = 'No comparison available yet.';
          return;
        }
        body.innerHTML = state.pmtaParsed.rows.map(r => `
          <tr>
            <td class="ltr">${escapeHtml(r.domain || '-')}</td>
            <td class="ltr">${escapeHtml(r.vmta || '-')}</td>
            <td class="ltr">${escapeHtml(r.ip || '-')}</td>
            <td class="ltr">${escapeHtml(r.helo || '-')}</td>
            <td class="ltr">${escapeHtml(r.dkimPath || '-')}</td>
            <td>${r.status.length ? statusBadge(r.status.join(' / '), 'warn') : statusBadge('OK', 'ok')}</td>
          </tr>
        `).join('');
        notices.className = state.pmtaParsed.notices.length ? 'notice warn' : 'notice ok';
        notices.innerHTML = state.pmtaParsed.notices.length ? state.pmtaParsed.notices.map(escapeHtml).join('<br>') : 'Config parsed successfully.';
        diffs.className = state.pmtaParsed.diffs?.length ? 'notice warn' : 'notice ok';
        diffs.innerHTML = state.pmtaParsed.diffs?.length ? state.pmtaParsed.diffs.map(escapeHtml).join('<br>') : 'No important differences were found between stored data and the current config.';
      }

      function comparePmtaWithStored(parsedRows, serverId) {
        const diffs = [];
        const serverIps = state.data.ips.filter(ip => ip.serverId === serverId);
        const serverDomains = state.data.domains.filter(d => d.serverId === serverId);
        parsedRows.forEach(r => {
          const foundDomain = serverDomains.find(d => d.domain === r.domain);
          const foundIp = serverIps.find(i => i.ip === r.ip);
          if (!foundDomain) diffs.push(`Domain not found in stored data: ${r.domain}`);
          if (!foundIp) diffs.push(`IP not found under the selected server: ${r.ip}`);
          if (foundDomain) {
            if (foundDomain.vmta !== r.vmta) diffs.push(`VMTA mismatch for ${r.domain}: stored=${foundDomain.vmta} / config=${r.vmta}`);
            if ((foundDomain.helo || '') !== (r.helo || '')) diffs.push(`HELO mismatch for ${r.domain}: stored=${foundDomain.helo || '-'} / config=${r.helo || '-'}`);
            if ((foundDomain.pemPath || '') !== (r.dkimPath || '')) diffs.push(`DKIM path mismatch for ${r.domain}: stored=${foundDomain.pemPath || '-'} / config=${r.dkimPath || '-'}`);
          }
        });
        return diffs;
      }

      function parsePmtaConfig(raw) {
        const result = { rows: [], notices: [], diffs: [], snapshot: { createdAt: Date.now() } };
        const lines = raw.split(/\r?\n/);
        const routing = [];
        const vmtaMap = {};
        const dkimMap = {};
        let currentVmta = null;
        let inPattern = false;

        for (const line of lines) {
          const trimmed = line.trim();
          if (/^<pattern-list\s+/i.test(trimmed)) inPattern = true;
          if (/^<\/pattern-list>/i.test(trimmed)) inPattern = false;

          const mailFromMatch = trimmed.match(/^mail-from\s+\/@(.+?)\$\/\s+virtual-mta=(.+)$/i);
          if (inPattern && mailFromMatch) {
            const regexBody = mailFromMatch[1];
            const vmta = mailFromMatch[2].trim();
            const guessedDomain = regexBody
              .replace(/\\\./g, '.')
              .replace(/^mail\./, 'mail.')
              .replace(/^s\d+\./, m => m)
              .replace(/\$$/, '')
              .replace(/\^/g, '')
              .replace(/\\/g, '');
            routing.push({ domainPattern: guessedDomain, vmta });
          }

          const vmtaOpen = trimmed.match(/^<virtual-mta\s+(.+?)>/i);
          if (vmtaOpen) {
            currentVmta = vmtaOpen[1].trim();
            vmtaMap[currentVmta] = vmtaMap[currentVmta] || { name: currentVmta };
            continue;
          }
          if (/^<\/virtual-mta>/i.test(trimmed)) {
            currentVmta = null;
            continue;
          }

          if (currentVmta) {
            const sourceHost = trimmed.match(/^smtp-source-host\s+(\S+)\s+(\S+)/i);
            if (sourceHost) {
              vmtaMap[currentVmta].ip = sourceHost[1];
              vmtaMap[currentVmta].helo = sourceHost[2];
            }
            const dkimLine = trimmed.match(/^domain-key\s+([^,]+),([^,]+),(.+)$/i);
            const dkimCommented = trimmed.match(/^#\s*domain-key\s+([^,]+),([^,]+),(.+)$/i);
            if (dkimLine) dkimMap[currentVmta] = { selector: dkimLine[1].trim(), domain: normalizeDomain(dkimLine[2]), path: dkimLine[3].trim(), commented: false };
            if (dkimCommented) dkimMap[currentVmta] = { selector: dkimCommented[1].trim(), domain: normalizeDomain(dkimCommented[2]), path: dkimCommented[3].trim(), commented: true };
          }
        }

        const uniqueDomains = new Map();
        routing.forEach(r => {
          let domain = r.domainPattern.replace(/^@/, '').replace(/\/$/, '').replace(/^mail\./, '').replace(/\\/g, '');
          const row = uniqueDomains.get(r.vmta) || { domain: '', vmta: r.vmta, ip: '', helo: '', dkimPath: '', dkimCommented: null, selector: 'dkim' };
          if (!row.domain || domain.length < row.domain.length) row.domain = domain;
          uniqueDomains.set(r.vmta, row);
        });

        Object.keys(vmtaMap).forEach(vmta => {
          const row = uniqueDomains.get(vmta) || { domain: '', vmta, ip: '', helo: '', dkimPath: '', dkimCommented: null, selector: 'dkim' };
          row.ip = vmtaMap[vmta].ip || '';
          row.helo = vmtaMap[vmta].helo || '';
          if (dkimMap[vmta]) {
            row.dkimPath = dkimMap[vmta].path;
            row.dkimCommented = dkimMap[vmta].commented;
            row.selector = dkimMap[vmta].selector;
            if (!row.domain) row.domain = dkimMap[vmta].domain;
          }
          uniqueDomains.set(vmta, row);
        });

        result.rows = Array.from(uniqueDomains.values()).map(row => {
          const status = [];
          if (!row.domain || !isValidDomain(row.domain)) status.push('domain?');
          if (!isValidIPv4(row.ip || '')) status.push('ip?');
          if (!row.helo) status.push('helo?');
          if (!row.dkimPath) status.push('dkim missing');
          if (row.dkimCommented) status.push('dkim commented');
          return { ...row, status };
        });

        if (!result.rows.length) result.notices.push('No rows were extracted from the config. Please verify the syntax.');
        if (result.rows.some(r => r.dkimCommented)) result.notices.push('Commented DKIM lines were detected. This may prevent actual DKIM signing.');
        if (result.rows.some(r => !r.ip)) result.notices.push('Some Virtual MTAs do not contain a clear smtp-source-host line.');
        return result;
      }

      function getNextIpLabel(serverId) {
        const count = state.data.ips.filter(x => x.serverId === serverId).length + 1;
        return `ip-mail-${String(count).padStart(2, '0')}`;
      }

      function buildDomainDraftFromIp(serverId, ipRecord) {
        const domain = normalizeDomain(ipRecord.extractedDomain || extractDomainFromPtr(ipRecord.ptr || ''));
        if (!isValidDomain(domain)) return null;
        return {
          serverId,
          ipId: ipRecord.id,
          domain,
          vmta: generateVmtaName(domain),
          helo: ipRecord.helo || ipRecord.ptr || '',
          selector: 'dkim',
          pemPath: `/root/${domain}/dkim.pem`,
          dmarc: generateDmarcValue(domain),
          spf: `v=spf1 ip4:${ipRecord.ip} ~all`,
          ptr: ipRecord.ptr || '',
          publicKey: '',
        };
      }

      function attachDkimResultToDraft(draft, dkimResult) {
        if (!draft || !dkimResult) return draft;
        draft.selector = dkimResult.selector || 'dkim';
        draft.pemPath = dkimResult.remotePath || draft.pemPath;
        draft.publicKey = dkimResult.publicKey || draft.publicKey || '';
        return draft;
      }

      function deleteDomain(domainId) {
        const domain = state.data.domains.find(x => x.id === domainId);
        if (!domain) return;
        state.data.domains = state.data.domains.filter(x => x.id !== domainId);
        const remainingForIp = state.data.domains.filter(x => x.ipId === domain.ipId);
        if (!remainingForIp.length) {
          const ipRec = state.data.ips.find(x => x.id === domain.ipId);
          if (ipRec) {
            const draft = buildDomainDraftFromIp(ipRec.serverId, ipRec);
            if (draft) state.data.domainDraftsByIp[ipRec.id] = draft;
          }
        }
        if (state.selected.type === 'domain' && state.selected.id === domainId) {
          state.selected = { type: 'ip', id: domain.ipId };
        }
      }

      function deleteIp(ipId) {
        const ipRec = state.data.ips.find(x => x.id === ipId);
        state.data.domains = state.data.domains.filter(x => x.ipId !== ipId);
        delete state.data.domainDraftsByIp[ipId];
        delete state.expandedIps[ipId];
        state.data.ips = state.data.ips.filter(x => x.id !== ipId);
        if (state.selected.type === 'ip' && state.selected.id === ipId) {
          state.selected = ipRec ? { type: 'server', id: ipRec.serverId } : { type: null, id: null };
        }
        if (state.selected.type === 'domain') {
          const stillExists = state.data.domains.some(x => x.id === state.selected.id);
          if (!stillExists) {
            state.selected = ipRec ? { type: 'server', id: ipRec.serverId } : { type: null, id: null };
          }
        }
      }

      function deleteServer(serverId) {
        const serverIps = state.data.ips.filter(x => x.serverId === serverId).map(x => x.id);
        state.data.domains = state.data.domains.filter(x => x.serverId !== serverId);
        state.data.ips = state.data.ips.filter(x => x.serverId !== serverId);
        state.data.servers = state.data.servers.filter(x => x.id !== serverId);
        serverIps.forEach(ipId => {
          delete state.data.domainDraftsByIp[ipId];
          delete state.expandedIps[ipId];
        });
        delete state.expandedServers[serverId];
        if (getCurrentContextServer()?.id === serverId) {
          state.selected = { type: null, id: null };
          state.showWorkspace = false;
          state.workspaceMode = 'auto';
        }
      }

      async function handleDeleteAction(type, id) {
        if (!type || !id) return;
        const confirmed = confirm(`Delete this ${type} and all linked child items?`);
        if (!confirmed) return;
        if (type === 'domain') deleteDomain(id);
        if (type === 'ip') deleteIp(id);
        if (type === 'server') deleteServer(id);
        await saveData();
      }

      function clearDomainAutoFields() {
        ['domainName','domainVmta','domainPtr','domainHelo','domainSpf','domainDmarc','domainPemPath','domainSelector','domainPublicKey'].forEach(id => {
          const el = document.getElementById(id);
          if (el) el.value = id === 'domainSelector' ? 'dkim' : '';
        });
      }

      function hydrateDomainAutoFields() {
        const serverSelect = document.getElementById('domainServerSelect');
        const ipSelect = document.getElementById('domainIpSelect');
        const help = document.getElementById('domainIpHelp');
        const contextIp = getCurrentContextIp();
        const contextServer = getCurrentContextServer();
        if (!ipSelect) return;
        if (contextServer && serverSelect) serverSelect.value = contextServer.id;
        if (contextIp) ipSelect.value = contextIp.id;
        if (help) {
          help.textContent = contextIp
            ? `Using IP context: ${contextIp.ip}`
            : 'No direct IP context detected. Select an IP or domain from the infrastructure tree.';
        }
      }

      function autoFillDomainFieldsFromSelectedIp() {
        const ipSelect = document.getElementById('domainIpSelect');
        if (!ipSelect) return;
        const ipId = ipSelect.value;
        const ip = state.data.ips.find(x => x.id === ipId);
        if (!ip) {
          clearDomainAutoFields();
          updateDomainMissingNotice();
          return;
        }
        const draft = state.data.domainDraftsByIp?.[ipId] || buildDomainDraftFromIp(ip.serverId, ip);
        if (!draft) {
          clearDomainAutoFields();
          updateDomainMissingNotice();
          return;
        }
        const fields = {
          domainName: draft.domain,
          domainVmta: draft.vmta,
          domainPtr: draft.ptr,
          domainHelo: draft.helo,
          domainSpf: draft.spf,
          domainDmarc: draft.dmarc,
          domainPemPath: draft.pemPath,
          domainSelector: 'dkim',
          domainPublicKey: draft.publicKey || '',
        };
        Object.entries(fields).forEach(([id, value]) => {
          const el = document.getElementById(id);
          if (el) el.value = value;
        });
        updateDomainMissingNotice();
      }

      function getDomainWorkspaceFormValues() {
        const ipId = document.getElementById('domainIpSelect')?.value || '';
        const ipRecord = state.data.ips.find(ip => ip.id === ipId) || null;
        return {
          serverId: document.getElementById('domainServerSelect')?.value || ipRecord?.serverId || '',
          ipId,
          domain: normalizeDomain(document.getElementById('domainName')?.value || ''),
          vmta: document.getElementById('domainVmta')?.value.trim() || '',
          helo: document.getElementById('domainHelo')?.value.trim() || '',
          selector: document.getElementById('domainSelector')?.value.trim() || 'dkim',
          pemPath: document.getElementById('domainPemPath')?.value.trim() || '',
          dmarc: document.getElementById('domainDmarc')?.value.trim() || '',
          spf: document.getElementById('domainSpf')?.value.trim() || '',
          ptr: document.getElementById('domainPtr')?.value.trim() || '',
          publicKey: document.getElementById('domainPublicKey')?.value.trim() || '',
        };
      }

      function syncCurrentDomainWorkspaceToState(overrides = {}) {
        const values = { ...getDomainWorkspaceFormValues(), ...overrides };
        const editingDomain = state.selected.type === 'domain'
          ? state.data.domains.find(x => x.id === state.selected.id) || null
          : null;

        if (editingDomain) {
          Object.assign(editingDomain, {
            serverId: values.serverId || editingDomain.serverId,
            ipId: values.ipId || editingDomain.ipId,
            domain: values.domain || editingDomain.domain,
            vmta: values.vmta || editingDomain.vmta,
            helo: values.helo || editingDomain.helo,
            selector: values.selector || editingDomain.selector || 'dkim',
            pemPath: values.pemPath || editingDomain.pemPath,
            dmarc: values.dmarc || editingDomain.dmarc,
            spf: values.spf || editingDomain.spf,
            ptr: values.ptr || editingDomain.ptr,
            publicKey: values.publicKey || editingDomain.publicKey || '',
          });
          return editingDomain;
        }

        if (!values.ipId) return null;
        const ipRecord = state.data.ips.find(ip => ip.id === values.ipId) || null;
        if (!ipRecord) return null;
        const existingDraft = state.data.domainDraftsByIp?.[values.ipId] || buildDomainDraftFromIp(ipRecord.serverId, ipRecord);
        if (!existingDraft) return null;
        state.data.domainDraftsByIp[values.ipId] = {
          ...existingDraft,
          serverId: values.serverId || existingDraft.serverId || ipRecord.serverId,
          ipId: values.ipId,
          domain: values.domain || existingDraft.domain,
          vmta: values.vmta || existingDraft.vmta,
          helo: values.helo || existingDraft.helo,
          selector: values.selector || existingDraft.selector || 'dkim',
          pemPath: values.pemPath || existingDraft.pemPath,
          dmarc: values.dmarc || existingDraft.dmarc,
          spf: values.spf || existingDraft.spf,
          ptr: values.ptr || existingDraft.ptr,
          publicKey: values.publicKey || existingDraft.publicKey || '',
        };
        return state.data.domainDraftsByIp[values.ipId];
      }

      function updateDomainMissingNotice() {
        const notice = document.getElementById('domainMissingNotice');
        const domain = normalizeDomain(document.getElementById('domainName')?.value || '');
        const publicKey = document.getElementById('domainPublicKey')?.value.trim() || '';
        if (!notice) return;
        if (!domain) {
          notice.className = 'notice warn';
          notice.textContent = 'Select an IP with a valid PTR first to prepare the domain data and DKIM generation flow.';
          return;
        }
        if (!publicKey) {
          notice.className = 'notice warn';
          notice.textContent = 'Warning: DKIM Public Key is empty. If you save now without clicking "Generate DKIM From PTR Domain", this domain will be marked as Missing in the server tree, IP node, and domain node.';
          return;
        }
        notice.className = 'notice ok';
        notice.textContent = 'DKIM public key is present. The domain no longer has a DKIM missing warning.';
      }

      async function checkServerSshFromWorkspace() {
        try {
          const payload = validateSshSettings(collectSshSettingsFromForm());
          const result = await apiCheckSsh(payload);
          const status = document.getElementById('serverSshStatus');
          if (status) {
            status.className = 'status ok';
            status.textContent = result.message || 'Connected';
          }
        } catch (error) {
          const status = document.getElementById('serverSshStatus');
          if (status) {
            status.className = 'status err';
            status.textContent = error.message || 'SSH check failed';
          }
        }
      }

      async function addServer() {
        const name = document.getElementById('serverName')?.value.trim() || '';
        const provider = document.getElementById('serverProvider')?.value.trim() || '';
        const accountUser = document.getElementById('serverAccountUser')?.value.trim() || '';
        const expiryDate = document.getElementById('serverExpiryDate')?.value || '';
        const notes = document.getElementById('serverNotes')?.value.trim() || '';
        const sshSettings = collectSshSettingsFromForm();
        if (!name) return alert('Please enter a server name');

        const editingServer = state.selected.type === 'server'
          ? state.data.servers.find(x => x.id === state.selected.id) || null
          : null;

        if (editingServer) {
          editingServer.name = name;
          editingServer.provider = provider;
          editingServer.accountUser = accountUser;
          editingServer.expiryDate = expiryDate;
          editingServer.notes = notes;
          Object.assign(editingServer, {
            sshHost: sshSettings.sshHost,
            sshPort: Number(sshSettings.sshPort || 22),
            sshTimeout: Number(sshSettings.sshTimeout || 20),
            sshUser: sshSettings.sshUser,
            sshPass: sshSettings.sshPass,
            dkimFilename: sshSettings.dkimFilename,
            keySize: Number(sshSettings.keySize || 2048),
          });
          state.selected = { type: 'server', id: editingServer.id };
        } else {
          const newServer = {
            id: uid('srv'),
            name,
            provider,
            expiryDate,
            accountUser,
            notes,
            sshHost: sshSettings.sshHost,
            sshPort: Number(sshSettings.sshPort || 22),
            sshTimeout: Number(sshSettings.sshTimeout || 20),
            sshUser: sshSettings.sshUser,
            sshPass: sshSettings.sshPass,
            dkimFilename: sshSettings.dkimFilename,
            keySize: Number(sshSettings.keySize || 2048),
            createdAt: Date.now(),
          };
          state.data.servers.push(newServer);
          state.selected = { type: 'server', id: newServer.id };
        }

        state.workspaceMode = 'auto';
        state.showWorkspace = true;
        await saveData();
      }

      async function addIp() {
        const serverId = document.getElementById('ipServerSelect')?.value || '';
        const ip = document.getElementById('ipAddress')?.value.trim() || '';
        const labelInput = document.getElementById('ipLabel')?.value.trim() || '';
        const ptrInput = document.getElementById('ipPtr')?.value.trim() || '';
        const heloInput = document.getElementById('ipHelo')?.value.trim() || '';
        if (!serverId) return alert('Please select a server');
        if (!isValidIPv4(ip)) return alert('Invalid IPv4 address');
        if (!ptrInput) return alert('Please enter PTR / Reverse DNS');

        const editingIp = state.selected.type === 'ip'
          ? state.data.ips.find(x => x.id === state.selected.id) || null
          : null;

        if (state.data.ips.some(x => x.ip === ip && (!editingIp || x.id !== editingIp.id))) {
          return alert('This IP already exists');
        }

        const ptr = normalizeDomain(ptrInput);
        const extractedDomain = extractDomainFromPtr(ptr);
        const helo = normalizeDomain(heloInput || ptr);
        const label = labelInput || getNextIpLabel(serverId);
        if (!isValidDomain(extractedDomain)) return alert('PTR must contain a valid hostname such as mail.example.com');

        let dkimResult = null;
        try {
          dkimResult = await generateSingleDkimForDomain(serverId, extractedDomain);
        } catch (error) {
          return alert(error.message || 'Automatic DKIM generation failed');
        }

        if (editingIp) {
          const previousServerId = editingIp.serverId;
          const previousIpId = editingIp.id;
          const previousExtractedDomain = editingIp.extractedDomain;
          editingIp.serverId = serverId;
          editingIp.ip = ip;
          editingIp.label = label;
          editingIp.ptr = ptr;
          editingIp.helo = helo;
          editingIp.extractedDomain = extractedDomain;

          state.data.domains.forEach(domain => {
            if (domain.ipId === previousIpId) {
              domain.serverId = serverId;
            }
          });

          const linkedDomains = state.data.domains.filter(x => x.ipId === previousIpId);
          if (!linkedDomains.length) {
            const draft = buildDomainDraftFromIp(serverId, editingIp);
            if (draft) state.data.domainDraftsByIp[editingIp.id] = attachDkimResultToDraft(draft, dkimResult);
          } else {
            delete state.data.domainDraftsByIp[editingIp.id];
            linkedDomains.forEach(domain => {
              if (!domain.domain || domain.domain === previousExtractedDomain) {
                domain.domain = extractedDomain;
                domain.vmta = generateVmtaName(extractedDomain);
                domain.dmarc = generateDmarcValue(extractedDomain);
              }
              domain.helo = helo;
              domain.spf = `v=spf1 ip4:${ip} ~all`;
              domain.ptr = ptr;
              domain.selector = dkimResult.selector || 'dkim';
              domain.pemPath = dkimResult.remotePath || domain.pemPath;
              domain.publicKey = dkimResult.publicKey || domain.publicKey || '';
            });
          }

          if (previousServerId !== serverId) {
            state.expandedServers[serverId] = true;
          }
          state.selected = { type: 'ip', id: editingIp.id };
        } else {
          const ipRecord = { id: uid('ip'), serverId, ip, label, ptr, helo, extractedDomain, createdAt: Date.now() };
          state.data.ips.push(ipRecord);
          const draft = buildDomainDraftFromIp(serverId, ipRecord);
          if (draft) state.data.domainDraftsByIp[ipRecord.id] = attachDkimResultToDraft(draft, dkimResult);
          state.selected = { type: 'ip', id: ipRecord.id };
        }

        state.workspaceMode = 'auto';
        state.showWorkspace = true;
        await saveData();
      }

      async function addDomain() {
        const serverId = document.getElementById('domainServerSelect')?.value || '';
        const ipId = document.getElementById('domainIpSelect')?.value || '';
        const domain = normalizeDomain(document.getElementById('domainName')?.value || '');
        const vmta = document.getElementById('domainVmta')?.value.trim() || '';
        const helo = document.getElementById('domainHelo')?.value.trim() || '';
        const selector = 'dkim';
        const pemPath = document.getElementById('domainPemPath')?.value.trim() || `/root/${domain}/dkim.pem`;
        const dmarc = document.getElementById('domainDmarc')?.value.trim() || '';
        const spf = document.getElementById('domainSpf')?.value.trim() || '';
        const ptr = document.getElementById('domainPtr')?.value.trim() || '';
        const publicKey = document.getElementById('domainPublicKey')?.value.trim() || '';

        if (!serverId) return alert('Please select a server');
        if (!ipId) return alert('Please select an IP from the selected server');
        if (!isValidDomain(domain)) return alert('Generated domain is invalid');
        if (!vmta) return alert('Generated Virtual MTA name is missing');
        if (!publicKey) {
          alert(`DKIM Public Key is empty for ${domain}. You may have forgotten to click "Generate DKIM From PTR Domain". The domain will still be saved, but it will be marked as Missing under the server, IP, and domain tree nodes until you generate or paste the key.`);
        }

        const editingDomain = state.selected.type === 'domain'
          ? state.data.domains.find(x => x.id === state.selected.id) || null
          : null;

        if (state.data.domains.some(x => x.domain === domain && (!editingDomain || x.id !== editingDomain.id))) {
          return alert('This domain already exists');
        }

        if (editingDomain) {
          editingDomain.serverId = serverId;
          editingDomain.ipId = ipId;
          editingDomain.domain = domain;
          editingDomain.vmta = vmta;
          editingDomain.helo = helo;
          editingDomain.selector = selector;
          editingDomain.pemPath = pemPath;
          editingDomain.dmarc = dmarc;
          editingDomain.spf = spf;
          editingDomain.ptr = ptr;
          editingDomain.publicKey = publicKey;
          state.selected = { type: 'domain', id: editingDomain.id };
        } else {
          const domainRecord = { id: uid('dom'), serverId, ipId, domain, vmta, helo, selector, pemPath, dmarc, spf, ptr, publicKey, createdAt: Date.now() };
          state.data.domains.push(domainRecord);
          state.selected = { type: 'domain', id: domainRecord.id };
        }

        if (!state.data.domainRegistry.some(x => normalizeDomain(x.domain) === domain)) {
          state.data.domainRegistry.push({ id: uid('regdom'), domain, provider: '', expiryDate: '', accountUser: '', note: '' });
        }
        delete state.data.domainDraftsByIp[ipId];
        state.workspaceMode = 'auto';
        state.showWorkspace = true;
        await saveData();
      }

      async function regenerateCurrentDomainDkim() {
        const serverId = document.getElementById('domainServerSelect')?.value || '';
        const domain = normalizeDomain(document.getElementById('domainName')?.value || '');
        if (!serverId) return alert('Please select a server');
        if (!isValidDomain(domain)) return alert('Generated domain is invalid');
        try {
          const item = await generateSingleDkimForDomain(serverId, domain);
          const publicKeyField = document.getElementById('domainPublicKey');
          const pemPathField = document.getElementById('domainPemPath');
          const selectorField = document.getElementById('domainSelector');
          if (publicKeyField) publicKeyField.value = item.publicKey || '';
          if (pemPathField) pemPathField.value = item.remotePath || '';
          if (selectorField) selectorField.value = item.selector || 'dkim';
          syncCurrentDomainWorkspaceToState({
            serverId,
            domain,
            selector: item.selector || 'dkim',
            pemPath: item.remotePath || '',
            publicKey: item.publicKey || '',
          });
          await saveData();
          updateDomainMissingNotice();
          alert(`DKIM generated successfully for ${domain}`);
        } catch (error) {
          alert(error.message || 'Failed to generate DKIM');
        }
      }

      async function pollCurrentDomainToNamecheap() {
        const config = getNamecheapConfig();
        if (!config.token || !config.username || !config.apiKey || !config.clientIp) {
          alert('Please save Namecheap configuration first from the NameChip Config popup.');
          openNamecheapModal();
          return;
        }

        const domain = normalizeDomain(document.getElementById('domainName')?.value || '');
        const helo = document.getElementById('domainHelo')?.value.trim() || '';
        const selector = document.getElementById('domainSelector')?.value.trim() || 'dkim';
        const spf = document.getElementById('domainSpf')?.value.trim() || '';
        const dmarc = document.getElementById('domainDmarc')?.value.trim() || '';
        const publicKey = document.getElementById('domainPublicKey')?.value.trim() || '';
        const ipId = document.getElementById('domainIpSelect')?.value || '';
        const ipRecord = state.data.ips.find(ip => ip.id === ipId);
        if (!ipRecord?.ip) return alert('This domain is missing a linked IP address.');

        const confirmed = confirm(`This will upsert A, MX, SPF, DKIM, and DMARC records for ${domain} in Namecheap. Continue?`);
        if (!confirmed) return;

        const button = document.getElementById('pollNamecheapBtn');
        const previousLabel = button?.textContent || 'Polling NameChip';
        if (button) {
          button.disabled = true;
          button.textContent = 'Polling...';
        }

        try {
          syncCurrentDomainWorkspaceToState({ serverId: document.getElementById('domainServerSelect')?.value || '', ipId });
          const result = await apiPollNamecheapDomain({
            config,
            domain,
            ipAddress: ipRecord.ip,
            helo,
            selector,
            spf,
            dmarc,
            publicKey,
            ttl: 1800,
          });
          const editingDomain = state.selected.type === 'domain'
            ? state.data.domains.find(x => x.id === state.selected.id) || null
            : null;
          if (editingDomain) {
            editingDomain.namecheapLastPolledAt = new Date().toISOString();
            editingDomain.namecheapLastAppliedRecords = result.appliedRecords || [];
          }
          await saveData();
          alert(result.message || `Namecheap DNS records were updated for ${domain}.`);
        } catch (error) {
          alert(error.message || 'Failed to poll Namecheap DNS records');
        } finally {
          if (button) {
            button.disabled = false;
            button.textContent = previousLabel;
          }
        }
      }

      async function addRegistryDomain() {
        const domain = normalizeDomain(document.getElementById('registryDomainName')?.value || '');
        const provider = document.getElementById('registryDomainProvider')?.value.trim() || '';
        const expiryDate = document.getElementById('registryDomainExpiryDate')?.value || '';
        const accountUser = document.getElementById('registryDomainAccountUser')?.value.trim() || '';
        const note = document.getElementById('registryDomainNote')?.value.trim() || '';
        if (!isValidDomain(domain)) return alert('Please enter a valid domain');
        if (state.data.domainRegistry.some(x => normalizeDomain(x.domain) === domain)) return alert('This registry domain already exists');
        state.data.domainRegistry.push({ id: uid('regdom'), domain, provider, expiryDate, accountUser, note });
        clearRegistryForm();
        state.registryPage = 1;
        await saveData();
      }

      async function updateRegistryDomain() {
        if (!state.selectedRegistryDomainId) return alert('Please choose a registry domain to edit first');
        const item = state.data.domainRegistry.find(x => x.id === state.selectedRegistryDomainId);
        if (!item) return alert('Selected registry domain was not found');
        const domain = normalizeDomain(document.getElementById('registryDomainName')?.value || '');
        const provider = document.getElementById('registryDomainProvider')?.value.trim() || '';
        const expiryDate = document.getElementById('registryDomainExpiryDate')?.value || '';
        const accountUser = document.getElementById('registryDomainAccountUser')?.value.trim() || '';
        const note = document.getElementById('registryDomainNote')?.value.trim() || '';
        if (!isValidDomain(domain)) return alert('Please enter a valid domain');
        const duplicate = state.data.domainRegistry.find(x => x.id !== item.id && normalizeDomain(x.domain) === domain);
        if (duplicate) return alert('Another registry domain already uses this domain');
        item.domain = domain;
        item.provider = provider;
        item.expiryDate = expiryDate;
        item.accountUser = accountUser;
        item.note = note;
        await saveData();
      }

      async function deleteRegistryDomain(registryId) {
        state.data.domainRegistry = state.data.domainRegistry.filter(x => x.id !== registryId);
        if (state.selectedRegistryDomainId === registryId) clearRegistryForm();
        const providerFilter = document.getElementById('registryProviderFilter')?.value || '';
        const accountFilter = document.getElementById('registryAccountFilter')?.value || '';
        const filteredCount = state.data.domainRegistry.filter(item => {
          const providerOk = !providerFilter || (item.provider || '').trim() === providerFilter;
          const accountOk = !accountFilter || (item.accountUser || '').trim() === accountFilter;
          return providerOk && accountOk;
        }).length;
        const totalPages = Math.max(1, Math.ceil(filteredCount / state.registryPageSize));
        if (state.registryPage > totalPages) state.registryPage = totalPages;
        await saveData();
      }

      function parsePmtaAction() {
        const raw = document.getElementById('pmtaConfig')?.value || '';
        if (!raw.trim()) return alert('Please paste a config first');
        const parsed = parsePmtaConfig(raw);
        const serverId = document.getElementById('pmtaServerSelect')?.value || '';
        if (serverId) parsed.diffs = comparePmtaWithStored(parsed.rows, serverId);
        state.pmtaParsed = parsed;
        renderPmtaResults();
      }

      async function applyPmtaAction() {
        if (!state.pmtaParsed) return alert('Please parse the config first');
        const serverId = document.getElementById('pmtaServerSelect')?.value || '';
        if (!serverId) return alert('Please select the target server');
        const server = state.data.servers.find(s => s.id === serverId);
        if (!server) return alert('Server not found');

        const errors = [];
        state.pmtaParsed.rows.forEach(r => {
          if (!isValidIPv4(r.ip || '')) errors.push(`Invalid IP: ${r.ip}`);
          const ipBelongs = state.data.ips.some(ip => ip.serverId === serverId && ip.ip === r.ip);
          if (!ipBelongs) errors.push(`IP does not belong to server ${server.name}: ${r.ip}`);
        });
        if (errors.length) return alert(errors.join('\n'));

        state.pmtaParsed.rows.forEach(r => {
          const ipRec = state.data.ips.find(ip => ip.serverId === serverId && ip.ip === r.ip);
          if (!ipRec) return;
          let domainRec = state.data.domains.find(d => d.serverId === serverId && d.domain === r.domain);
          if (!domainRec) {
            domainRec = {
              id: uid('dom'),
              serverId,
              ipId: ipRec.id,
              domain: normalizeDomain(r.domain),
              vmta: r.vmta,
              helo: r.helo,
              selector: r.selector || 'dkim',
              pemPath: r.dkimPath || `/root/${normalizeDomain(r.domain)}/dkim.pem`,
              dmarc: '',
              spf: `v=spf1 ip4:${r.ip} ~all`,
              ptr: r.helo,
              publicKey: '',
              createdAt: Date.now(),
            };
            state.data.domains.push(domainRec);
          } else {
            domainRec.ipId = ipRec.id;
            domainRec.vmta = r.vmta || domainRec.vmta;
            domainRec.helo = r.helo || domainRec.helo;
            domainRec.ptr = domainRec.ptr || r.helo;
            domainRec.selector = r.selector || domainRec.selector || 'dkim';
            domainRec.pemPath = r.dkimPath || domainRec.pemPath || `/root/${normalizeDomain(r.domain)}/dkim.pem`;
            if (!domainRec.spf) domainRec.spf = `v=spf1 ip4:${r.ip} ~all`;
          }
        });

        state.data.snapshots.push({
          id: uid('snap'),
          serverId,
          name: document.getElementById('pmtaSnapshotName')?.value.trim() || `snapshot-${new Date().toISOString()}`,
          raw: document.getElementById('pmtaConfig')?.value || '',
          parsedAt: Date.now(),
        });
        await saveData();
        alert('The config was applied internally to the selected server successfully.');
      }

      function validatePmtaAction() {
        if (!state.pmtaParsed) return alert('Please parse the config first');
        const issues = [];
        state.pmtaParsed.rows.forEach(r => {
          if (!r.domain) issues.push('A row exists without a domain');
          if (!r.vmta) issues.push(`A domain exists without VMTA: ${r.domain}`);
          if (!isValidIPv4(r.ip || '')) issues.push(`Invalid IP: ${r.ip}`);
          if (!r.helo) issues.push(`Missing HELO: ${r.domain}`);
          if (!r.dkimPath) issues.push(`Missing DKIM path: ${r.domain}`);
          if (r.dkimCommented) issues.push(`Commented DKIM line detected: ${r.domain}`);
        });
        alert(issues.length ? issues.join('\n') : 'Internal validation looks good.');
      }

      async function pollPmtaConfigInServer() {
        const serverId = getCurrentSelectedServerId();
        if (!serverId) return alert('Please select a Server, Domain, or IP linked to a server first');
        const server = state.data.servers.find(x => x.id === serverId);
        if (!server) return alert('Server not found');

        const generated = generatePmtaForServer(serverId);
        if (!generated) return alert('This server needs five valid IP/domain mappings before polling the full config into the server');

        let sshSettings;
        try {
          sshSettings = validateSshSettings(getServerSshSettings(server));
        } catch (error) {
          return alert(error.message || 'SSH settings are incomplete');
        }

        renderGeneratedOutput(generated);
        const confirmed = confirm(`This will replace the full file ${PMTA_REMOTE_CONFIG_PATH} on ${server.name}. Continue?`);
        if (!confirmed) return;

        const button = document.getElementById('pollPmtaInServerBtn');
        const previousLabel = button?.textContent || 'Polling in Server';
        if (button) {
          button.disabled = true;
          button.textContent = 'Polling...';
        }

        try {
          const result = await apiPollPmtaConfig({
            ...sshSettings,
            configContent: generated,
          });
          server.pmtaConfigFingerprint = generated.trim();
          server.pmtaConfigPolledAt = new Date().toISOString();
          server.pmtaConfigRemotePath = result.remotePath || PMTA_REMOTE_CONFIG_PATH;
          await saveData();
          alert(result.message || `PowerMTA config was polled to ${server.name} successfully.`);
        } catch (error) {
          alert(error.message || 'Failed to poll PowerMTA config into the server');
        } finally {
          if (button) {
            button.disabled = false;
            button.textContent = previousLabel;
          }
        }
      }

      function generatePmtaForDomain(domain) {
        const ip = state.data.ips.find(i => i.id === domain.ipId);
        if (!ip) return '';
        return `# ${domain.domain} -> ${ip.ip}\n<virtual-mta ${domain.vmta}>\n    smtp-source-host ${ip.ip} ${domain.helo}\n    domain-key ${domain.selector},${domain.domain},${domain.pemPath}\n</virtual-mta>`;
      }

      function generatePmtaForServer(serverId) {
        return generateFullPmtaForServer(serverId);
      }

      function getPmtaGenerationBundle(serverId) {
        function labelRank(label) {
          const clean = String(label || '').toLowerCase().trim();
          if (clean.indexOf('main') >= 0) return 1;
          let digits = '';
          for (let i = 0; i < clean.length; i += 1) {
            const ch = clean[i];
            if (ch >= '0' && ch <= '9') digits += ch;
          }
          return digits ? parseInt(digits, 10) : 9999;
        }

        function escapeDomainForPmtaRegex(domain) {
          return String(domain || '').replace(/\./g, '\\\\.');
        }

        const sortedIps = state.data.ips
          .filter(ip => ip.serverId === serverId)
          .slice()
          .sort((a, b) => {
            const aNum = labelRank(a.label);
            const bNum = labelRank(b.label);
            if (aNum !== bNum) return aNum - bNum;
            return String(a.ip).localeCompare(String(b.ip));
          });

        const mappings = sortedIps.map((ip) => {
          const linkedDomain = state.data.domains.find(d => d.ipId === ip.id) || null;
          const draftDomain = state.data.domainDraftsByIp && state.data.domainDraftsByIp[ip.id]
            ? state.data.domainDraftsByIp[ip.id]
            : null;

          const domainName = normalizeDomain(
            (linkedDomain && linkedDomain.domain) ||
            (draftDomain && draftDomain.domain) ||
            extractDomainFromPtr(ip.ptr || '') ||
            ''
          );

          return {
            domain: domainName,
            ip: ip.ip,
            helo: (linkedDomain && linkedDomain.helo) || ip.helo || ip.ptr || '',
            ptr: (linkedDomain && linkedDomain.ptr) || ip.ptr || ip.helo || '',
            vmta: (linkedDomain && linkedDomain.vmta) || generateVmtaName(domainName),
            selector: (linkedDomain && linkedDomain.selector) || 'dkim',
            pemPath: (linkedDomain && linkedDomain.pemPath) || ('/root/' + domainName + '/dkim.pem')
          };
        });

        if (!mappings.length) return { output: '', mappings, reason: 'no-mappings' };
        if (mappings.some(item => !item.domain || !isValidDomain(item.domain))) return { output: '', mappings, reason: 'invalid-domain' };
        if (mappings.length < 5) return { output: '', mappings, reason: 'needs-five-ips' };

        const fallback = mappings[mappings.length - 1];
        let output = getStrictPmtaTemplate();

        const replacements = {
          '[POSTMASTER_DOMAIN]': fallback.domain,
          '[LISTENER_IP]': mappings[0].ip,
          '[FALLBACK_VMTA]': fallback.vmta,
        };

        mappings.slice(0, 5).forEach((item, index) => {
          const slot = index + 1;
          replacements[`[DOMAIN${slot}]`] = item.domain;
          replacements[`[IP${slot}]`] = item.ip;
          replacements[`[PTR${slot}]`] = item.ptr;
          replacements[`[HELO${slot}]`] = item.helo || item.ptr;
          replacements[`[VMTA${slot}]`] = item.vmta;
          replacements[`[PEM${slot}]`] = item.pemPath;
          replacements[`[SELECTOR${slot}]`] = item.selector || 'dkim';
          replacements[`[DOMAIN${slot}_ESC]`] = escapeDomainForPmtaRegex(item.domain);
        });

        Object.entries(replacements).forEach(([placeholder, value]) => {
          output = output.split(placeholder).join(String(value || ''));
        });

        return { output, mappings, reason: '' };
      }

      function generateFullPmtaForServer(serverId) {
        return getPmtaGenerationBundle(serverId).output || '';
      }

      function getStrictPmtaTemplate() {
        return String.raw`############################################################################
# PowerMTA configuration update for strict 1:1 domain/IP routing
#
# Domain -> dedicated IP (with matching HELO/PTR)
#   [DOMAIN1] -> [IP1]   (PTR: [PTR1])
#   [DOMAIN2] -> [IP2]   (PTR: [PTR2])
#   [DOMAIN3] -> [IP3]   (PTR: [PTR3])
#   [DOMAIN4] -> [IP4]   (PTR: [PTR4])
#   [DOMAIN5] -> [IP5]   (PTR: [PTR5])
#
# Goal:
#   Every sender domain uses ONLY its assigned IP.
#
# Notes:
# - This routing is enforced by MAIL FROM (envelope-from) pattern matching.
# - X-VirtualMTA override is disabled.
# - If MAIL FROM is not one of the five domains, message is routed to
#   [FALLBACK_VMTA] via default-virtual-mta (safe fallback).
############################################################################

postmaster abuse@[POSTMASTER_DOMAIN]

############################################################################
# LISTENERS
############################################################################
smtp-listener [LISTENER_IP]:8080
# smtp-listener 0.0.0.0:8080

<source 0/0>
    log-connections yes
    log-commands yes
    allow-unencrypted-plain-auth no
</source>

sync-msg-create false
sync-msg-update false
run-as-root no

log-file /var/log/pmta/log
spool /var/spool/pmta

############################################################################
# ACCOUNTING / DIAGNOSTICS
############################################################################
<acct-file /var/log/pmta/acct.csv>
    max-size 50M
</acct-file>

<acct-file /var/log/pmta/diag.csv>
    move-interval 1d
    delete-after never
    records t
</acct-file>

############################################################################
# HTTP MANAGEMENT (lock down in production)
############################################################################
http-mgmt-port 1993
http-access 0.0.0.0/0 admin
http-access [IP1]/0 monitor

############################################################################
# STRICT DOMAIN ROUTING (MAIL FROM -> dedicated virtual-mta)
############################################################################
<pattern-list strict-mailfrom-routing>
    # [DOMAIN1] -> [IP1]
    mail-from /@[DOMAIN1_ESC]$/      virtual-mta=[VMTA1]
    mail-from /@mail\.[DOMAIN1_ESC]$/ virtual-mta=[VMTA1]

    # [DOMAIN2] -> [IP2]
    mail-from /@[DOMAIN2_ESC]$/      virtual-mta=[VMTA2]
    mail-from /@mail\.[DOMAIN2_ESC]$/ virtual-mta=[VMTA2]

    # [DOMAIN3] -> [IP3]
    mail-from /@[DOMAIN3_ESC]$/      virtual-mta=[VMTA3]
    mail-from /@mail\.[DOMAIN3_ESC]$/ virtual-mta=[VMTA3]

    # [DOMAIN4] -> [IP4]
    mail-from /@[DOMAIN4_ESC]$/      virtual-mta=[VMTA4]
    mail-from /@mail\.[DOMAIN4_ESC]$/ virtual-mta=[VMTA4]

    # [DOMAIN5] -> [IP5]
    mail-from /@[DOMAIN5_ESC]$/      virtual-mta=[VMTA5]
    mail-from /@mail\.[DOMAIN5_ESC]$/ virtual-mta=[VMTA5]
</pattern-list>

############################################################################
# AUTHENTICATED SMTP SUBMISSION SOURCE
############################################################################
<smtp-user scampia>
    password CHANGE_ME_STRONG_PASSWORD
    source {pmta-auth}
</smtp-user>

<source {pmta-auth}>
    smtp-service yes
    require-auth true
    always-allow-relaying yes

    # Enforce routing from MAIL FROM only
    process-x-virtual-mta no
    pattern-list strict-mailfrom-routing
    default-virtual-mta [FALLBACK_VMTA]

    remove-received-headers true
    add-received-header false
    hide-message-source true
</source>

############################################################################
# LOCAL API/INJECTION SOURCE
############################################################################
<source 127.0.0.1>
    always-allow-api-submission yes
    add-message-id-header yes
    retain-x-job yes
    retain-x-virtual-mta yes
    verp-default yes
    process-x-envid yes
    process-x-job yes
    jobid-header X-Mailer-RecptId
    process-x-virtual-mta yes
</source>

############################################################################
# VIRTUAL MTAS (dedicated source IP + matching HELO/PTR)
############################################################################

# [DOMAIN1] -> [IP1]
<virtual-mta [VMTA1]>
    smtp-source-host [IP1] [HELO1]
    domain-key [SELECTOR1],[DOMAIN1],[PEM1]
    <domain *>
        max-cold-virtual-mta-msg 400/day
        max-msg-rate 10000/h
    </domain>
</virtual-mta>

# [DOMAIN2] -> [IP2]
<virtual-mta [VMTA2]>
    smtp-source-host [IP2] [HELO2]
    domain-key [SELECTOR2],[DOMAIN2],[PEM2]
    <domain *>
        max-cold-virtual-mta-msg 400/day
        max-msg-rate 10000/h
    </domain>
</virtual-mta>

# [DOMAIN3] -> [IP3]
<virtual-mta [VMTA3]>
    smtp-source-host [IP3] [HELO3]
    domain-key [SELECTOR3],[DOMAIN3],[PEM3]
    <domain *>
        max-cold-virtual-mta-msg 400/day
        max-msg-rate 10000/h
    </domain>
</virtual-mta>

# [DOMAIN4] -> [IP4]
<virtual-mta [VMTA4]>
    smtp-source-host [IP4] [HELO4]
    domain-key [SELECTOR4],[DOMAIN4],[PEM4]
    <domain *>
        max-cold-virtual-mta-msg 400/day
        max-msg-rate 10000/h
    </domain>
</virtual-mta>

# [DOMAIN5] -> [IP5]
<virtual-mta [VMTA5]>
    smtp-source-host [IP5] [HELO5]
    domain-key [SELECTOR5],[DOMAIN5],[PEM5]
    <domain *>
        max-cold-virtual-mta-msg 400/day
        max-msg-rate 10000/h
    </domain>
</virtual-mta>

############################################################################
# ISP / BACKOFF RULES
############################################################################

domain-macro hotmail hotmail.com,msn.com,hotmail.co.uk,hotmail.fr,live.com,hotmail.it,hotmail.de,email.msn.com,email.hotmail.com,email.msn.com,hotmail.com,live.com,msn.com,webtv.com,webtv.net
<domain $hotmail>
    max-smtp-out 1
    max-msg-rate 250/h
</domain>

domain-macro yahoo yahoo.com,yahoo.ca,rocketmail.com,ymail.com,yahoo.com.au,geocities.com,yahoo.com.mx,yahoo.com.br,altavista.com,ameritech.net,att.net,bellsouth.net,attbroadband.com,attcanada.net,attglobal.com,attglobal.net,attnet.com,attworldnet.com,bellatlantic.net,bellatlantic.net,bellsouth.com,bellsouth.net,flash.net,netzero.net,nvbell.net,pacbell.net,prodigy.com,prodigy.net,sbcglobal.net,sbcglobal.net,snet.net,swbell.com,swbell.net,toast.net,usa.net,verizon.com,verizon.net,verizonmail.com,vzwpix.com,wans.net,worldnet.att.net,yahoo.net
<domain $yahoo>
    max-msg-per-connection 2
    max-msg-rate 250/h
</domain>

domain-macro aol aol.com,aim.com,aim.net,cs.com,netscape.com,wmconnect.net,netscape.net,cs.com,mail.com,wmconnect.com,icqmail.com,email.com,usa.com
<domain $aol>
    max-msg-rate 250/h
</domain>

domain-macro gmail gmail.com,googlemail.com
<domain $gmail>
    max-msg-rate 250/h
</domain>

<domain comcast.net>
    max-msg-rate 250/h
</domain>

<domain tdameritrade.com>
    max-msg-rate 250/h
</domain>

<domain ameritrade.com>
    max-msg-rate 250/h
</domain>

<domain charterinternet.com>
    max-msg-rate 250/h
</domain>

<domain comcast.com>
    max-msg-rate 250/h
</domain>

<domain comcastwork.com>
    max-msg-rate 250/h
</domain>

<domain cox.com>
    max-msg-rate 250/h
</domain>

<domain cox.net>
    max-msg-rate 250/h
</domain>

<domain coxinternet.com>
    max-msg-rate 250/h
</domain>

<domain cox-internet.com>
    max-msg-rate 250/h
</domain>

<domain suddenlink.net>
    max-msg-rate 250/h
</domain>

<domain windjammer.net>
    max-msg-rate 250/h
</domain>

<domain centurylink.com>
    max-msg-rate 250/h
</domain>

<domain centurylink.net>
    max-msg-rate 250/h
</domain>

<domain centurytel.com>
    max-msg-rate 250/h
</domain>

<domain centurytel.net>
    max-msg-rate 250/h
</domain>

<domain cswnet.com>
    max-msg-rate 250/h
</domain>

<domain emadisonriver.com>
    max-msg-rate 250/h
</domain>

<domain emadisonriver.net>
    max-msg-rate 250/h
</domain>

<domain embarq.com>
    max-msg-rate 250/h
</domain>

<domain embarq.net>
    max-msg-rate 250/h
</domain>

<domain embarqmail.com>
    max-msg-rate 250/h
</domain>

<domain grics.net>
    max-msg-rate 250/h
</domain>

<domain gulftel.com>
    max-msg-rate 250/h
</domain>

<domain mebtel.net>
    max-msg-rate 250/h
</domain>

<domain qwest.net>
    max-msg-rate 250/h
</domain>

<domain uswest.com>
    max-msg-rate 250/h
</domain>

<domain uswest.net>
    max-msg-rate 250/h
</domain>

<domain swestmail.com>
    max-msg-rate 250/h
</domain>

<domain uswestmail.net>
    max-msg-rate 250/h
</domain>

<domain fuse.com>
    max-msg-rate 250/h
</domain>

<domain fuse.net>
    max-msg-rate 250/h
</domain>

<domain zoomnet.net>
    max-msg-rate 250/h
</domain>

<domain zoomtown.com>
    max-msg-rate 250/h
</domain>

<domain zoomtown.net>
    max-msg-rate 250/h
</domain>

<domain earthlink.com>
    max-msg-rate 250/h
</domain>

<domain earthlink.net>
    max-msg-rate 250/h
</domain>

<domain mindspring.com>
    max-msg-rate 250/h
</domain>

<domain netcom.com>
    max-msg-rate 250/h
</domain>

<domain Inbox.com>
    max-msg-rate 250/h
</domain>

<domain outblaze.com>
    max-msg-rate 250/h
</domain>

<domain excite.com>
    max-msg-rate 250/h
</domain>

<domain iwon.com>
    max-msg-rate 250/h
</domain>

<domain angelfire.com>
    max-msg-rate 250/h
</domain>

<domain lycos.com>
    max-msg-rate 250/h
</domain>

<domain lycosmail.com>
    max-msg-rate 250/h
</domain>

<domain mailcity.com>
    max-msg-rate 250/h
</domain>

<domain sprintpcs.com>
    max-msg-rate 250/h
</domain>

<domain rr.com>
    max-msg-rate 250/h
</domain>

<domain adelphia.com>
    max-msg-rate 250/h
</domain>

<domain adelphia.net>
    max-msg-rate 250/h
</domain>

<domain insightbb.com>
    max-msg-rate 250/h
</domain>

<domain roadrunner.com>
    max-msg-rate 250/h
</domain>

<domain roadrunner.net>
    max-msg-rate 250/h
</domain>

<domain tmomail.net>
    max-msg-rate 250/h
</domain>

domain-macro gmx gmx.net,gmx.com,gmx.de,gmx.us,mail.com,web.de
<domain $gmx>
    max-msg-rate 250/h
</domain>

<domain juno.com>
    max-msg-rate 250/h
</domain>

<domain netzero.com>
    max-msg-rate 250/h
</domain>

<domain unitedonline.net>
    max-msg-rate 250/h
</domain>

<domain concentric.net>
    max-msg-rate 250/h
</domain>

# default domain settings
<domain *>
    max-smtp-out 2
    max-msg-per-connection 100
    max-errors-per-connection 10
    max-msg-rate 10000/h

    smtp-greeting-timeout 5m

    bounce-upon-no-mx yes
    assume-delivery-upon-data-termination-timeout yes

    retry-after 10m
    bounce-after 24h

    smtp-pattern-list blocking-errors

    backoff-max-msg-rate 1/m
    backoff-retry-after 20m
    backoff-notify ""
    backoff-to-normal-after-delivery yes
    backoff-to-normal-after 1h

    dkim-sign yes
    ignore-8bitmime true

    use-starttls yes
    require-starttls no
</domain>

<smtp-pattern-list common-errors>
    reply /generating high volumes of.* complaints from AOL/    mode=backoff
    reply /Excessive unknown recipients - possible Open Relay/  mode=backoff
    reply /^421 .* too many errors/                             mode=backoff
    reply /blocked.*spamhaus/                                   mode=backoff
    reply /451 Rejected/                                        mode=backoff
</smtp-pattern-list>

<smtp-pattern-list blocking-errors>
    # AOL
    reply /421 .* SERVICE NOT AVAILABLE/ mode=backoff
    reply /generating high volumes of.* complaints from AOL/ mode=backoff
    reply /554 .*aol.com/ mode=backoff
    reply /421dynt1/ mode=backoff
    reply /HVU:B1/ mode=backoff
    reply /DNS:NR/ mode=backoff
    reply /RLY:NW/ mode=backoff
    reply /DYN:T1/ mode=backoff
    reply /RLY:BD/ mode=backoff
    reply /RLY:CH2/ mode=backoff
    reply /RLY:CH2/ mode=backoff

    # Yahoo
    reply /421 .* Please try again later/ mode=backoff
    reply /421 Message temporarily deferred/ mode=backoff
    reply /VS3-IP5 Excessive unknown recipients/ mode=backoff
    reply /VSS-IP Excessive unknown recipients/ mode=backoff
    reply /[GL01] Message from/ mode=backoff
    reply /[TS01] Messages from/ mode=backoff
    reply /[TS02] Messages from/ mode=backoff
    reply /[TS03] All messages from/ mode=backoff

    # Hotmail
    reply /exceeded the rate limit/ mode=backoff
    reply /exceeded the connection limit/ mode=backoff
    reply /Mail rejected by Windows Live Hotmail for policy reasons/ mode=backoff

    # Adelphia
    reply /421 Message Rejected/ mode=backoff
    reply /Client host rejected/ mode=backoff
    reply /blocked using UCEProtect/ mode=backoff

    # Road Runner
    reply /Mail Refused/ mode=backoff
    reply /421 Exceeded allowable connection time/ mode=backoff
    reply /amIBlockedByRR/ mode=backoff
    reply /block-lookup/ mode=backoff
    reply /Too many concurrent connections from source IP/ mode=backoff

    # General
    reply /too many/ mode=backoff
    reply /Exceeded allowable connection time/ mode=backoff
    reply /Connection rate limit exceeded/ mode=backoff
    reply /refused your connection/ mode=backoff
    reply /try again later/ mode=backoff
    reply /try later/ mode=backoff
    reply /550 RBL/ mode=backoff
    reply /TDC internal RBL/ mode=backoff
    reply /connection refused/ mode=backoff
    reply /please see www.spamhaus.org/ mode=backoff
    reply /Message Rejected/ mode=backoff
    reply /refused by antispam/ mode=backoff
    reply /Service not available/ mode=backoff
    reply /currently blocked/ mode=backoff
    reply /locally blacklisted/ mode=backoff
    reply /not currently accepting mail from your ip/ mode=backoff
    reply /421.*closing connection/ mode=backoff
    reply /421.*Lost connection/ mode=backoff
    reply /476 connections from your host are denied/ mode=backoff
    reply /421 Connection cannot be established/ mode=backoff
    reply /421 temporary envelope failure/ mode=backoff
    reply /421 4\.4\.2 Timeout while waiting for command/ mode=backoff
    reply /450 Requested action aborted/ mode=backoff
    reply /550 Access denied/ mode=backoff
    reply /421rlynw/ mode=backoff
    reply /permanently deferred/ mode=backoff
    reply /d+.d+.d+.d+ blocked/ mode=backoff
</smtp-pattern-list>

############################################################################
# BOUNCE RULES
############################################################################

<bounce-category-patterns>
    /spam/ spam-related
    /junk mail/ spam-related
    /blacklist/ spam-related
    /blocked/ spam-related
    /\bU\.?C\.?E\.?\b/ spam-related
    /\bAdv(ertisements?)?\b/ spam-related
    /unsolicited/ spam-related
    /\b(open)?RBL\b/ spam-related
    /realtime blackhole/ spam-related
    /\bvirus\b/ virus-related
    /message +content/ content-related
    /content +rejected/ content-related
    /quota/ quota-issues
    /limit exceeded/ quota-issues
    /mailbox +(is +)?full/ quota-issues
    /sender ((verify|verification) failed|could not be verified|address rejected|domain must exist)/ invalid-sender
    /unable to verify sender/ invalid-sender
    /requires valid sender domain/ invalid-sender
    /bad sender's system address/ invalid-sender
    /No MX for envelope sender domain/ invalid-sender
    /^[45].4.4/ routing-errors
    /no mail hosts for domain/ invalid-sender
    /REQUESTED ACTION NOT TAKEN: DNS FAILURE/ invalid-sender
    /Domain of sender address/ invalid-sender
    /return MX does not exist/ invalid-sender
    /Invalid sender domain/ invalid-sender
    /Verification failed/ invalid-sender
    /\bstorage\b/ quota-issues
    /(user|mailbox|recipient|rcpt|local part|address|account|mail drop|ad(d?)ressee)
    (has|has been|is)? *(currently|temporarily+)?(disabled|expired|inactive|not activated)
    / inactive-mailbox
    /(conta|usu.rio) inativ(a|o)
    / inactive-mailbox
    /Too many (bad|invalid|unknown|illegal|unavailable) (user|mailbox|recipient|rcpt|local part|address|account|mail drop|ad(d?)ressee)/other
    /(No such|bad|invalid|unknown|illegal|unavailable) (local +)?(user|mailbox|recipient|rcpt|local part|address|account|mail drop|ad(d?)ressee)
    / bad-mailbox
    /(user|mailbox|recipient|rcpt|local part|address|account|mail drop|ad(d?)ressee) +(S+@S+ +)?(not (a +)?valid|not known|not here|not
    found|does not exist|bad|invalid|unknown|illegal|unavailable)/ bad-mailbox
    /S+@S+ +(is +)?(not (a +)?valid|not known|not here|not found|does not exist|bad|invalid|unknown|illegal|unavailable)/ bad-mailbox
    /no mailbox here by that name/ bad-mailbox
    /my badrcptto list/ bad-mailbox
    /not our customer/ bad-mailbox
    /no longer (valid|available)/ bad-mailbox
    /have a S+ account/ bad-mailbox
    /\brelay(ing)?/ relaying-issues
    /domain (retired|bad|invalid|unknown|illegal|unavailable)/ bad-domain
    /domain no longer in use/ bad-domain
    /domain (S+ +)?(is +)?obsolete/ bad-domain
    /denied/ policy-related
    /prohibit/ policy-related
    /refused/ policy-related
    /allowed/ policy-related
    /banned/ policy-related
    /policy/ policy-related
    /suspicious activity/ policy-related
    /bad sequence/ protocol-errors
    /syntax error/ protocol-errors
    /\broute\b/ routing-errors
    /\bunroutable\b/ routing-errors
    /\bunrouteable\b/ routing-errors

    /Invalid 7bit DATA/ content-related
    /^2.d+.d+;/ success
    /^[45].1.[1346];/ bad-mailbox
    /^[45].1.2/ bad-domain
    /^[45].1.[78];/ invalid-sender
    /^[45].2.0;/ bad-mailbox
    /^[45].2.1;/ inactive-mailbox
    /^[45].2.2;/ quota-issues
    /^[45].3.3;/ content-related
    /^[45].3.5;/ bad-configuration
    /^[45].4.1;/ no-answer-from-host
    /^[45].4.2;/ bad-connection
    /^[45].4.[36];/ routing-errors
    /^[45].4.7;/ message-expired
    /^[45].5.3;/ policy-related
    /^[45].5.d+;/ protocol-errors
    /^[45].6.d+;/ content-related
    /^[45].7.[012];/ policy-related
    /^[45].7.7;/ content-related
    // other
</bounce-category-patterns>

############################################################################
# END
############################################################################`;
      }

      function renderGeneratedOutput(text = '') {
        const el = document.getElementById('generatedOutput');
        if (!el) return;
        const normalized = String(text)
          .replace(/\r\n/g, '\n')
          .replace(/\n/g, '\n')
          .replace(/\t/g, '\t');
        el.value = normalized;
      }

      function exportData() {
        openJsonModal('export', getCurrentExportJson());
      }

      async function resetAll() {
        const confirmText = prompt('Type DELETE to remove all database data');
        if (confirmText !== 'DELETE') return;
        await apiResetData();
        clearDataFromLocalCache();
        state.data = defaultData();
        state.selected = { type: null, id: null };
        state.pmtaParsed = null;
        state.showWorkspace = false;
        state.workspaceMode = 'auto';
        renderAll();
        alert('All database data has been removed');
      }

      function renderPmtaServerSelect() {
        const select = document.getElementById('pmtaServerSelect');
        if (!select) return;
        const current = select.value;
        select.innerHTML = `<option value="">-- Select --</option>` + state.data.servers.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('');
        if (current) select.value = current;
      }

      function renderAll() {
        renderStats();
        renderPmtaServerSelect();
        renderInfraTree();
        renderWorkspace();
        renderOverview();
        renderDnsSummary(state.selected.type === 'domain' ? state.data.domains.find(x => x.id === state.selected.id) : null);
        renderReadiness(state.selected.type === 'domain' ? state.data.domains.find(x => x.id === state.selected.id) : null);
        renderPmtaResults();
        renderDomainsRegistry();
      }

      async function handleTreeClick(event) {
        const deleteTarget = event.target.closest('[data-delete-type][data-delete-id]');
        if (deleteTarget) {
          event.stopPropagation();
          await handleDeleteAction(deleteTarget.dataset.deleteType, deleteTarget.dataset.deleteId);
          return;
        }
        const toggleTarget = event.target.closest('[data-server-toggle][data-server-id]');
        if (toggleTarget) {
          event.stopPropagation();
          const serverId = toggleTarget.dataset.serverId;
          const mode = toggleTarget.dataset.serverToggle;
          const serverIps = state.data.ips.filter(ip => ip.serverId === serverId);
          state.treeCollapsed = false;

          if (mode === 'domains') {
            const shouldExpandAllDomains = !serverIps.every(ip => !!state.expandedIps[ip.id]) || !state.expandedServers[serverId];
            state.expandedServers[serverId] = true;
            if (shouldExpandAllDomains) {
              serverIps.forEach(ip => {
                state.expandedIps[ip.id] = true;
              });
            } else {
              serverIps.forEach(ip => {
                delete state.expandedIps[ip.id];
              });
            }
            renderInfraTree();
            return;
          }

          state.expandedServers[serverId] = !state.expandedServers[serverId];
          if (!state.expandedServers[serverId]) {
            serverIps.forEach(ip => delete state.expandedIps[ip.id]);
          }
          renderInfraTree();
          return;
        }

        const ipToggleTarget = event.target.closest('[data-ip-toggle][data-ip-id]');
        if (ipToggleTarget) {
          event.stopPropagation();
          const ipId = ipToggleTarget.dataset.ipId;
          const ip = state.data.ips.find(x => x.id === ipId);
          if (ip) {
            state.treeCollapsed = false;
            state.expandedServers[ip.serverId] = true;
            state.expandedIps[ipId] = !state.expandedIps[ipId];
          }
          renderInfraTree();
          return;
        }
        const selectTarget = event.target.closest('[data-select-type][data-select-id]');
        if (selectTarget) {
          state.selected = { type: selectTarget.dataset.selectType, id: selectTarget.dataset.selectId };
          const selectedServer = getCurrentContextServer();
          if (state.selected.type === 'server' && selectedServer) {
            state.expandedServers[selectedServer.id] = !state.expandedServers[selectedServer.id];
            if (!state.expandedServers[selectedServer.id]) {
              state.data.ips.filter(ip => ip.serverId === selectedServer.id).forEach(ip => delete state.expandedIps[ip.id]);
            }
          }
          if (state.selected.type === 'ip') {
            const ip = getCurrentContextIp();
            if (selectedServer) state.expandedServers[selectedServer.id] = true;
            if (ip) state.expandedIps[ip.id] = !state.expandedIps[ip.id];
          }
          if (state.selected.type === 'domain') {
            const ip = getCurrentContextIp();
            if (selectedServer) state.expandedServers[selectedServer.id] = true;
            if (ip) state.expandedIps[ip.id] = true;
          }
          state.workspaceMode = 'auto';
          state.showWorkspace = true;
          renderAll();
          return;
        }

        const draftTarget = event.target.closest('[data-open-domain-draft]');
        if (draftTarget) {
          const ipId = draftTarget.dataset.openDomainDraft;
          state.selected = { type: 'domainDraft', id: ipId };
          const selectedServer = getCurrentContextServer();
          if (selectedServer) {
            state.expandedServers[selectedServer.id] = true;
            state.expandedIps[ipId] = true;
          }
          state.workspaceMode = 'domain';
          state.showWorkspace = true;
          renderAll();
        }
      }

      function bindEvents() {
        document.getElementById('exportBtn')?.addEventListener('click', exportData);
        document.getElementById('importBtn')?.addEventListener('click', () => openJsonModal('import', ''));
        document.getElementById('bulkDkimBtn')?.addEventListener('click', openBulkDkimModal);
        document.getElementById('namecheapConfigBtn')?.addEventListener('click', openNamecheapModal);
        document.getElementById('domainsRegistryBtn')?.addEventListener('click', () => {
          document.querySelectorAll('#mainTabs .tab').forEach(t => t.classList.remove('active'));
          document.getElementById('domainsRegistryTab')?.classList.add('active');
          document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
          document.getElementById('domainsRegistryPanel')?.classList.add('active');
        });
        document.getElementById('treeExpandBtn')?.addEventListener('click', () => {
          state.treeCollapsed = false;
          state.data.servers.forEach(server => {
            state.expandedServers[server.id] = true;
          });
          state.data.ips.forEach(ip => {
            state.expandedIps[ip.id] = true;
          });
          renderInfraTree();
        });
        document.getElementById('treeCollapseBtn')?.addEventListener('click', () => {
          state.treeCollapsed = true;
          state.expandedServers = {};
          state.expandedIps = {};
          state.showWorkspace = false;
          renderAll();
        });
        document.getElementById('addNewBtn')?.addEventListener('click', () => {
          state.selected = { type: null, id: null };
          state.workspaceMode = 'auto';
          state.showWorkspace = true;
          renderAll();
        });
        document.getElementById('infraTree')?.addEventListener('click', (e) => { handleTreeClick(e); });

        document.getElementById('workspaceContent')?.addEventListener('input', (e) => {
          if (e.target.id === 'ipPtr') {
            const helo = document.getElementById('ipHelo');
            if (helo) helo.value = normalizeDomain(e.target.value.trim());
          }
          if (e.target.id === 'domainPublicKey') {
            updateDomainMissingNotice();
          }
        });

        document.getElementById('workspaceContent')?.addEventListener('click', async (e) => {
          if (e.target.id === 'addServerBtn') await addServer();
          if (e.target.id === 'addIpBtn') await addIp();
          if (e.target.id === 'addDomainBtn') await addDomain();
          if (e.target.id === 'serverCheckSshBtn') await checkServerSshFromWorkspace();
          if (e.target.id === 'generateDomainDkimBtn') await regenerateCurrentDomainDkim();
          if (e.target.id === 'pollNamecheapBtn') await pollCurrentDomainToNamecheap();

          if (e.target.id === 'openServerWorkspaceBtn') {
            state.workspaceMode = 'auto';
            state.showWorkspace = true;
            if (!state.selected.type || state.selected.type === 'domainDraft') {
              state.selected = { type: null, id: null };
            }
            renderAll();
          }

          if (e.target.id === 'openIpWorkspaceBtn') {
            state.workspaceMode = 'ip';
            state.showWorkspace = true;
            renderAll();
          }

          if (e.target.id === 'openDomainWorkspaceBtn') {
            state.workspaceMode = 'domain';
            state.showWorkspace = true;
            renderAll();
          }
        });

        document.getElementById('addRegistryDomainBtn')?.addEventListener('click', addRegistryDomain);
        document.getElementById('updateRegistryDomainBtn')?.addEventListener('click', updateRegistryDomain);
        document.getElementById('clearRegistryDomainBtn')?.addEventListener('click', clearRegistryForm);
        document.getElementById('registryProviderFilter')?.addEventListener('change', () => {
          state.registryPage = 1;
          renderDomainsRegistry();
        });
        document.getElementById('registryAccountFilter')?.addEventListener('change', () => {
          state.registryPage = 1;
          renderDomainsRegistry();
        });
        document.getElementById('domainsRegistryContent')?.addEventListener('click', async (e) => {
          if (e.target.id === 'registryPrevPageBtn') {
            if (state.registryPage > 1) {
              state.registryPage -= 1;
              renderDomainsRegistry();
            }
            return;
          }
          if (e.target.id === 'registryNextPageBtn') {
            const providerFilter = document.getElementById('registryProviderFilter')?.value || '';
            const accountFilter = document.getElementById('registryAccountFilter')?.value || '';
            const filteredCount = state.data.domainRegistry.filter(item => {
              const providerOk = !providerFilter || (item.provider || '').trim() === providerFilter;
              const accountOk = !accountFilter || (item.accountUser || '').trim() === accountFilter;
              return providerOk && accountOk;
            }).length;
            const totalPages = Math.max(1, Math.ceil(filteredCount / state.registryPageSize));
            if (state.registryPage < totalPages) {
              state.registryPage += 1;
              renderDomainsRegistry();
            }
            return;
          }
          const actionEl = e.target.closest('[data-registry-action][data-registry-id]');
          if (!actionEl) return;
          const registryId = actionEl.dataset.registryId;
          const action = actionEl.dataset.registryAction;
          const item = state.data.domainRegistry.find(x => x.id === registryId);
          if (!item) return;
          if (action === 'edit') {
            state.selectedRegistryDomainId = registryId;
            populateRegistryForm(item);
            renderDomainsRegistry();
            return;
          }
          if (action === 'delete') {
            const confirmed = confirm('Delete this registry domain?');
            if (!confirmed) return;
            await deleteRegistryDomain(registryId);
          }
        });

        document.getElementById('parsePmtaBtn')?.addEventListener('click', parsePmtaAction);
        document.getElementById('applyPmtaBtn')?.addEventListener('click', applyPmtaAction);
        document.getElementById('validatePmtaBtn')?.addEventListener('click', validatePmtaAction);
        document.getElementById('clearPmtaBtn')?.addEventListener('click', () => {
          const pmtaConfig = document.getElementById('pmtaConfig');
          if (pmtaConfig) pmtaConfig.value = '';
          state.pmtaParsed = null;
          renderPmtaResults();
        });
        document.getElementById('generateCurrentDomainPmtaBtn')?.addEventListener('click', () => {
          if (state.selected.type !== 'domain') return alert('Please select a domain first');
          const domain = state.data.domains.find(x => x.id === state.selected.id);
          if (domain) renderGeneratedOutput(generatePmtaForDomain(domain));
        });
        document.getElementById('generateServerPmtaBtn')?.addEventListener('click', () => {
          const serverId = getCurrentSelectedServerId();
          if (!serverId) return alert('Please select a Server, Domain, or IP linked to a server first');
          const generated = generatePmtaForServer(serverId);
          if (!generated) return alert('This server needs valid IPs and linked domains before generating the full config');
          renderGeneratedOutput(generated);
        });
        document.getElementById('pollPmtaInServerBtn')?.addEventListener('click', pollPmtaConfigInServer);

        document.getElementById('mainTabs')?.addEventListener('click', (e) => {
          const tab = e.target.closest('.tab');
          if (!tab) return;
          document.querySelectorAll('#mainTabs .tab').forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          const target = tab.dataset.tab;
          document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
          document.getElementById(target)?.classList.add('active');
        });

        document.body.addEventListener('click', async (e) => {
          if (e.target.id === 'jsonModalCloseBtn' || e.target.id === 'closeJsonModalBtn') {
            closeJsonModal();
            return;
          }
          if (e.target.id === 'bulkDkimCloseBtn' || e.target.id === 'bulkDkimCloseFooterBtn' || e.target.id === 'bulkDkimOverlay') {
            closeBulkDkimModal();
            return;
          }
          if (e.target.id === 'namecheapCloseBtn' || e.target.id === 'namecheapCloseFooterBtn' || e.target.id === 'namecheapOverlay') {
            closeNamecheapModal();
            return;
          }
          if (e.target.id === 'copyJsonBtn') {
            copyJsonToClipboard();
            return;
          }
          if (e.target.id === 'namecheapTryBtn') {
            try {
              await tryNamecheapConnection();
            } catch (error) {
              setNamecheapNotice(error.message || 'Namecheap connection failed.', 'err');
            }
            return;
          }
          if (e.target.id === 'namecheapSaveBtn') {
            try {
              await saveNamecheapConfig();
            } catch (error) {
              setNamecheapNotice(error.message || 'Failed to save Namecheap config.', 'err');
            }
            return;
          }
          if (e.target.dataset.copyTarget) {
            try {
              await copyElementText(e.target.dataset.copyTarget);
              setBulkDkimNotice('Copied to clipboard.', 'ok');
            } catch (error) {
              setBulkDkimNotice(error.message || 'Clipboard copy failed.', 'err');
            }
            return;
          }
          if (e.target.id === 'downloadJsonBtn') {
            downloadJsonText('mail-infra-dashboard-data.json', document.getElementById('jsonModalTextarea')?.value || getCurrentExportJson());
            setJsonModalNotice('JSON download started.', 'ok');
            return;
          }
          if (e.target.id === 'mergeJsonBtn') {
            await handleMergeImport();
            return;
          }
          if (e.target.id === 'replaceJsonBtn') {
            const confirmed = confirm('This will replace all current stored data with the new JSON. Continue?');
            if (!confirmed) return;
            await handleReplaceImport();
            return;
          }
          if (e.target.id === 'formatJsonBtn') {
            formatJsonTextarea();
            return;
          }
          if (e.target.id === 'clearJsonTextareaBtn') {
            const textarea = document.getElementById('jsonModalTextarea');
            if (textarea) textarea.value = '';
            setJsonModalNotice('Textarea cleared.', 'warn');
            return;
          }
          if (e.target.id === 'bulkAddRowBtn') {
            const server = getServerById(document.getElementById('bulkDkimServerId')?.value || '');
            const rows = Array.from(document.querySelectorAll('#bulkDkimRows tr')).map(row => ({
              domain: row.querySelector('[data-bulk-domain]')?.value.trim() || '',
              selector: row.querySelector('[data-bulk-selector]')?.value.trim() || 'dkim',
            }));
            rows.push({ domain: '', selector: `s${rows.length + 1}` });
            renderBulkDkimModal(server, rows);
            return;
          }
          const removeRowBtn = e.target.closest('[data-bulk-remove-row]');
          if (removeRowBtn) {
            const server = getServerById(document.getElementById('bulkDkimServerId')?.value || '');
            const indexToRemove = Number(removeRowBtn.dataset.bulkRemoveRow);
            const rows = Array.from(document.querySelectorAll('#bulkDkimRows tr')).map(row => ({
              domain: row.querySelector('[data-bulk-domain]')?.value.trim() || '',
              selector: row.querySelector('[data-bulk-selector]')?.value.trim() || 'dkim',
            })).filter((_, index) => index !== indexToRemove);
            renderBulkDkimModal(server, rows.length ? rows : [{ domain: '', selector: 'dkim' }]);
            return;
          }
          if (e.target.id === 'bulkCheckSshBtn') {
            try {
              const payload = validateSshSettings(collectBulkDkimPayload());
              const result = await apiCheckSsh(payload);
              setBulkDkimNotice(result.message || 'SSH connection succeeded.', 'ok');
            } catch (error) {
              setBulkDkimNotice(error.message || 'SSH connection failed.', 'err');
            }
            return;
          }
          if (e.target.id === 'bulkSaveToServerBtn') {
            try {
              const payload = validateSshSettings(collectBulkDkimPayload());
              const serverId = payload.serverId || '';
              writeSshSettingsToServer(serverId, payload);
              await saveData();
              setBulkDkimNotice('SSH settings saved into the selected server.', 'ok');
              renderBulkDkimModal(getServerById(serverId), payload.domains.length ? payload.domains : [{ domain: '', selector: 'dkim' }]);
            } catch (error) {
              setBulkDkimNotice(error.message || 'Failed to save SSH settings.', 'err');
            }
            return;
          }
          if (e.target.id === 'bulkGenerateBtn') {
            try {
              const payload = validateSshSettings(collectBulkDkimPayload());
              if (!payload.domains.length) throw new Error('Please add at least one domain');
              const result = await apiGenerateDkim(payload);
              state.bulkDkimResults = result;
              if (payload.serverId) {
                writeSshSettingsToServer(payload.serverId, payload);
                await saveData();
              }
              renderBulkDkimModal(getServerById(payload.serverId), payload.domains);
              setBulkDkimNotice(`Generated ${result.items?.length || 0} DKIM record(s) successfully.`, 'ok');
            } catch (error) {
              setBulkDkimNotice(error.message || 'Bulk DKIM generation failed.', 'err');
            }
            return;
          }
          if (e.target.id === 'jsonModalOverlay') {
            closeJsonModal();
          }
        });

        document.addEventListener('keydown', (e) => {
          if (e.key === 'Escape' && document.getElementById('jsonModalOverlay')?.classList.contains('show')) {
            closeJsonModal();
          }
          if (e.key === 'Escape' && document.getElementById('bulkDkimOverlay')?.classList.contains('show')) {
            closeBulkDkimModal();
          }
          if (e.key === 'Escape' && document.getElementById('namecheapOverlay')?.classList.contains('show')) {
            closeNamecheapModal();
          }
        });
      }

      function runSelfTests() {
        console.assert(isValidIPv4('194.116.172.135') === true, 'IPv4 test failed');
        console.assert(isValidIPv4('999.999.1.1') === false, 'Invalid IPv4 test failed');
        console.assert(extractDomainFromPtr('mail.example.com') === 'example.com', 'PTR extraction failed');
        console.assert(generateVmtaName('send-me-emails.com') === 'pmta-send-me-emails', 'VMTA generation failed');
        console.assert(generateDmarcValue('example.com').includes('dmarc@example.com'), 'DMARC generation failed');
        console.assert(isValidDomain('example.com') === true, 'Domain validation failed');
        console.assert(isValidPemPath('example.com', '/root/example.com/dkim.pem') === true, 'PEM path validation failed');
        console.assert(getServerExpiryStatus('').label === 'No expiry', 'Expiry fallback failed');
        console.assert(findLinkedServerNameForDomain('missing-example.com') === '', 'Linked server fallback failed');
        console.assert(getServerExpiryStatus('2099-01-01').label.includes('Expires in'), 'Expiry future status failed');
        console.assert(Array.isArray(findLinkedIpsForDomain('missing-example.com')) && findLinkedIpsForDomain('missing-example.com').length === 0, 'Linked IP fallback failed');
      }

      bindEvents();
      runSelfTests();
      const cachedData = loadDataFromLocalCache();
      try {
        const backendData = loadDataFromBackendObject(await apiGetData());
        state.data = backendData;
        if (hasMeaningfulData(backendData) || !cachedData) {
          persistDataToLocalCache(backendData);
        } else {
          state.data = cachedData;
          await apiSaveData(state.data);
          persistDataToLocalCache(state.data);
        }
      } catch (error) {
        state.data = cachedData || defaultData();
      }
      renderAll();
    });
  </script>
</body>
</html>'''


def default_data():
    return {
        "servers": [],
        "ips": [],
        "domains": [],
        "domainRegistry": [],
        "snapshots": [],
        "domainDraftsByIp": {},
        "namecheapConfig": normalize_namecheap_config({}),
    }


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA synchronous = NORMAL')
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_storage (
                storage_key TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        columns = {row['name'] for row in conn.execute("PRAGMA table_info(app_storage)").fetchall()}
        if 'created_at' not in columns:
            conn.execute("ALTER TABLE app_storage ADD COLUMN created_at TIMESTAMP")
        if 'updated_at' not in columns:
            conn.execute("ALTER TABLE app_storage ADD COLUMN updated_at TIMESTAMP")

        conn.execute(
            "UPDATE app_storage SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        )
        conn.execute(
            "UPDATE app_storage SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"
        )
        conn.commit()


def normalize_data(data):
    if not isinstance(data, dict):
        raise ValueError("Invalid JSON payload")

    normalized = default_data()
    normalized.update(data)

    for field in ['servers', 'ips', 'domains', 'domainRegistry', 'snapshots']:
        value = normalized.get(field)
        if value is None:
            normalized[field] = []
        elif not isinstance(value, list):
            raise ValueError(f"Field '{field}' must be a list")

    drafts = normalized.get('domainDraftsByIp')
    if drafts is None:
        normalized['domainDraftsByIp'] = {}
    elif not isinstance(drafts, dict):
        raise ValueError("Field 'domainDraftsByIp' must be an object")

    normalized['namecheapConfig'] = normalize_namecheap_config(normalized.get('namecheapConfig') or {})

    return normalized


def get_data():
    init_db()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT payload FROM app_storage WHERE storage_key = ?",
            (STORAGE_KEY,),
        ).fetchone()
    if not row:
        return default_data()
    try:
        payload = json.loads(row["payload"])
        return normalize_data(payload)
    except Exception:
        return default_data()


def set_data(data):
    normalized = normalize_data(data)
    payload = json.dumps(normalized, ensure_ascii=False)
    init_db()
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO app_storage (storage_key, payload, created_at, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(storage_key) DO UPDATE SET
                payload = excluded.payload,
                updated_at = CURRENT_TIMESTAMP
            """,
            (STORAGE_KEY, payload),
        )
        conn.commit()
    return normalized


@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/api/data', methods=['GET'])
def api_get_data():
    return jsonify(get_data())


@app.route('/api/data', methods=['POST'])
def api_post_data():
    payload = request.get_json(silent=True)
    if payload is None and request.data:
        try:
            payload = json.loads(request.data.decode('utf-8'))
        except Exception:
            payload = None
    try:
        saved = set_data(payload)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "data": saved})


@app.route('/api/data', methods=['DELETE'])
def api_delete_data():
    return jsonify({"ok": True, "data": set_data(default_data())})


@app.route('/api/dkim/check-ssh', methods=['POST'])
def api_check_ssh():
    payload = request.get_json(silent=True) or {}
    ssh_host = (payload.get('sshHost') or '').strip()
    ssh_user = (payload.get('sshUser') or '').strip()
    ssh_pass = payload.get('sshPass') or ''
    ssh_port = clean_int(payload.get('sshPort', 22), 22)
    ssh_timeout = clean_int(payload.get('sshTimeout', 20), 20)

    if not ssh_host or not ssh_user:
        return jsonify({'ok': False, 'error': 'Missing SSH host or username.'}), 400

    client = None
    sftp = None
    try:
        client, sftp = ssh_connect_sftp(ssh_host, ssh_port, ssh_user, ssh_pass, timeout=ssh_timeout)
        sftp.listdir('.')
        return jsonify({'ok': True, 'message': f'✅ Connected to {ssh_host}:{ssh_port} (SFTP)'})
    except Exception as exc:
        return jsonify({'ok': False, 'error': f'❌ Connection failed: {exc}'}), 400
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass


@app.route('/api/dkim/generate', methods=['POST'])
def api_generate_dkim():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(run_dkim_generation(payload))
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400


@app.route('/api/pmta/poll-config', methods=['POST'])
def api_poll_pmta_config():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(run_pmta_config_polling(payload))
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400


@app.route('/api/namecheap/test', methods=['POST'])
def api_namecheap_test():
    payload = request.get_json(silent=True) or {}
    try:
        client = build_namecheap_client(payload)
        domains = client.list_domains(page=1, page_size=100)
        return jsonify(
            {
                'ok': True,
                'domains': domains,
                'message': f'Connected to Namecheap successfully. Loaded {len(domains)} domains.',
            }
        )
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400


@app.route('/api/namecheap/poll-domain', methods=['POST'])
def api_namecheap_poll_domain():
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(poll_namecheap_dns(payload))
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
