#!/usr/bin/env python3
"""Приёмник webhook для проверки на стенде (W3-08): слушает только 127.0.0.1 (центр разрешает http лишь на loopback),
печатает по строке на запрос: тип события, event_id, номер обращения, состояние и отметку «повтор» для уже виденного
event_id. Тело целиком не сохраняет; подпись не проверяет (это делает получатель в эксплуатации, OPERATIONS.md, раздел 9).

Запуск: python3 scripts/webhook_sink.py [--port 18080] [--fail N]  — --fail: первые N запросов ответить 500
(проверка повторной доставки). Адрес для «Уведомлений»: http://127.0.0.1:18080/itsm
Самопроверка: python3 scripts/webhook_sink.py --selftest
"""
import argparse
import json
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SEEN = {}
LOCK = threading.Lock()
STATE = {'fail': 0}


def line(headers, body):
    try:
        payload = json.loads(body)
    except ValueError:
        return 'not-json'
    data = payload.get('data') or {}
    event_id = headers.get('X-SurveyScan-Event-Id', '')
    with LOCK:
        SEEN[event_id] = SEEN.get(event_id, 0) + 1
        repeat = SEEN[event_id] > 1
    return ' '.join([payload.get('event_type', '?'), event_id, data.get('number', '-'), data.get('state', '-'),
                     data.get('metric', ''), 'ПОВТОР' if repeat else '']).strip()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(min(int(self.headers.get('Content-Length') or 0), 1 << 20))
        with LOCK:
            fail = STATE['fail'] > 0
            if fail:
                STATE['fail'] -= 1
        print(('500 ' if fail else '204 ') + line(self.headers, body), flush=True)
        self.send_response(500 if fail else 204)
        self.end_headers()

    def log_message(self, *args):
        pass


def selftest():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_address[1]}/itsm'
    body = json.dumps({'event_type': 'ticket.created.v1', 'data': {'number': 'INC-2026-000001', 'state': 'new'}}).encode()
    codes = []
    STATE['fail'] = 1
    for _ in range(3):
        req = urllib.request.Request(url, body, {'X-SurveyScan-Event-Id': 'e1', 'Content-Type': 'application/json'})
        try:
            codes.append(urllib.request.urlopen(req).status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
    server.shutdown()
    assert codes == [500, 204, 204] and SEEN['e1'] == 3, (codes, SEEN)
    print('selftest ok')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=18080)
    p.add_argument('--fail', type=int, default=0)
    p.add_argument('--selftest', action='store_true')
    a = p.parse_args()
    if a.selftest:
        return selftest()
    STATE['fail'] = a.fail
    print(f'listening http://127.0.0.1:{a.port}/itsm', flush=True)
    ThreadingHTTPServer(('127.0.0.1', a.port), Handler).serve_forever()


if __name__ == '__main__':
    sys.exit(main())
