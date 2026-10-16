# -*- coding: utf-8 -*-
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime


def check_ssl(url):
    try:
        url = url if '://' in url else 'https://' + url
        host = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (expires - datetime.now()).days
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                return {'valid': True, 'issuer': issuer, 'expires': expires.isoformat(), 'days_left': days, 'tls_version': ssock.version(), 'score': 100 if days > 30 else 60}
    except Exception as e:
        return {'valid': False, 'error': str(e), 'score': 0}


def check_headers(url):
    try:
        url = url if '://' in url else 'https://' + url
        r = requests.head(url, timeout=10, allow_redirects=True)
        h = r.headers
        sh = {
            'Strict-Transport-Security': h.get('Strict-Transport-Security'),
            'X-Content-Type-Options': h.get('X-Content-Type-Options'),
            'X-Frame-Options': h.get('X-Frame-Options'),
            'Content-Security-Policy': h.get('Content-Security-Policy'),
            'X-XSS-Protection': h.get('X-XSS-Protection'),
            'Referrer-Policy': h.get('Referrer-Policy'),
        }
        present = sum(1 for v in sh.values() if v)
        return {'headers': sh, 'present': present, 'total': len(sh), 'score': int((present / len(sh)) * 100)}
    except Exception as e:
        return {'error': str(e), 'score': 0}


def check_ports(host):
    ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    dangerous = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'}
    risks = [dangerous[p] for p in open_ports if p in dangerous]
    return {'open': open_ports, 'risks': risks, 'score': max(0, 100 - len(risks) * 20)}


def full_scan(url):
    host = urlparse(url if '://' in url else 'https://' + url).hostname
    ssl_r = check_ssl(url)
    hdr_r = check_headers(url)
    ports_r = check_ports(host)
    scores = [ssl_r.get('score', 0), hdr_r.get('score', 0), ports_r.get('score', 0)]
    overall = sum(scores) // len(scores)
    return {'url': url, 'overall_score': overall, 'ssl': ssl_r, 'headers': hdr_r, 'ports': ports_r}