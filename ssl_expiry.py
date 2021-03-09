#!/usr/bin/env python3
# Author: Lucas Roelser <roesler.lucas@gmail.com>
# URL: https://github.com/LucasRoesler/ssl-expiry-check
# Modified from serverlesscode.com/post/ssl-expiration-alerts-with-lambda/

import datetime
import fileinput
import os
import socket
import ssl
import time

def ssl_expiry_datetime(hostname: str, port: int) -> datetime.datetime:
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    print(f'Connect to {hostname}:{port}')
    conn.connect((hostname, port))
    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)


def ssl_valid_time_remaining(hostname: str) -> datetime.timedelta:
    """Get the number of days left in a cert's lifetime."""
    expires = ssl_expiry_datetime(hostname)
    print(f'SSL cert for {hostname}:{port} expires at {expires.isoformat()}')
    return expires - datetime.datetime.utcnow()


def test_host(hostname: str, port: int, buffer_days: int=30) -> str:
    """Return test message for hostname cert expiration."""
    try:
        will_expire_in = ssl_valid_time_remaining(hostname, port)
    except ssl.CertificateError as e:
        return f'{hostname}:{port} cert error {e}'
    except ssl.SSLError as e:
        return f'{hostname}:{port} cert error {e}'
    except socket.timeout as e:
        return f'{hostname}:{port} could not connect'
    else:
        if will_expire_in < datetime.timedelta(days=0):
            return f'{hostname}:{port} cert will expired'
        elif will_expire_in < datetime.timedelta(days=buffer_days):
            return f'{hostname}:{port} cert will expire in {will_expire_in}'
        else:
            return f'{hostname}:{port} cert is fine'


if __name__ == '__main__':
    start = time.time()
    for host in fileinput.input():
        host = host.strip()
        if ':' in host:
            domain = host.split(':')[0]
            port = host.split(':')[1]
        else:
            domain = host
            port = 443
        print(f'Testing host {domain}:{port}')
        message = test_host(domain, port)

    while True:
        time.sleep(1)

