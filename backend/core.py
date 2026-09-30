"""Dependency-free detection and parameterized SQL persistence for synthetic data only."""
from datetime import datetime
from pathlib import Path
import re
import sqlite3
from threading import RLock

FIELDS = ('id', 'timestamp', 'type', 'account', 'ip', 'role', 'source')
TYPES = {'login_failed', 'login_success', 'role_changed', 'session_ended'}
RULES = {'TG-001': ('Repeated authentication failures', 'high'),
         'TG-002': ('Successful login after repeated failures', 'critical'),
         'TG-003': ('Privileged role assigned', 'medium')}

def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

def validate_events(data):
    if not isinstance(data, list) or not 1 <= len(data) <= 2000:
        raise ValueError('Expected 1–2,000 synthetic lab events.')
    ids = set()
    result = []
    for i, event in enumerate(data):
        message = f'Event {i + 1} does not match the synthetic lab schema.'
        if not isinstance(event, dict) or set(event) != set(FIELDS) or not all(isinstance(v, str) for v in event.values()):
            raise ValueError(message)
        valid = (re.fullmatch(r'EV-[A-Za-z0-9-]{1,24}', event['id']) and event['id'] not in ids
                 and re.fullmatch(r'demo-[a-z0-9-]{1,24}', event['account'])
                 and re.fullmatch(r'(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}', event['ip'])
                 and int(event['ip'].split('.')[-1]) <= 255
                 and re.fullmatch(r'2026-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z', event['timestamp'])
                 and event['type'] in TYPES and event['role'] in {'user', 'admin'}
                 and event['source'] == 'identity-lab')
        if not valid:
            raise ValueError(message)
        try:
            timestamp(event['timestamp'])
        except ValueError:
            raise ValueError(message) from None
        ids.add(event['id'])
        result.append({k: event[k] for k in FIELDS})
    return sorted(result, key=lambda e: timestamp(e['timestamp']))

def detect(events, enabled=None):
    enabled = set(RULES) if enabled is None else set(enabled)
    buckets, emitted, alerts = {}, set(), []
    def emit(rule_id, event, evidence):
        key = (rule_id, event['account'], event['ip'])
        if key in emitted or rule_id not in enabled:
            return
        emitted.add(key)
        title, severity = RULES[rule_id]
        alerts.append(dict(id=f'TG-{1001 + len(alerts)}', ruleId=rule_id,
                           title=title, severity=severity, account=event['account'],
                           time=event['timestamp'], evidence=[e['id'] for e in evidence]))
    for event in sorted(events, key=lambda e: timestamp(e['timestamp'])):
        key = (event['account'], event['ip'])
        previous = [e for e in buckets.get(key, []) if (timestamp(event['timestamp']) - timestamp(e['timestamp'])).total_seconds() <= 600]
        buckets[key] = previous
        if event['type'] == 'login_failed':
            previous.append(event)
            if len(previous) >= 5:
                emit('TG-001', event, previous)
        if event['type'] == 'login_success' and len(previous) >= 5:
            emit('TG-002', event, previous + [event])
        if event['type'] == 'role_changed' and event['role'] == 'admin':
            emit('TG-003', event, [event])
    # Input order is stable; severity is the first sort key, latest event the second.
    alerts.sort(key=lambda a: timestamp(a['time']), reverse=True)
    alerts.sort(key=lambda a: {'critical': 0, 'high': 1, 'medium': 2}[a['severity']])
    return alerts

class LabStore:
    def __init__(self, path=':memory:'):
        self.lock = RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(Path(__file__).with_name('schema.sql').read_text())

    def replace(self, events):
        clean = validate_events(events)  # Validate before deleting the prior dataset.
        with self.lock, self.db:
            self.db.execute('DELETE FROM events')
            self.db.executemany('INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)',
                                [tuple(e[k] for k in FIELDS) for e in clean])
        return len(clean)

    def events(self, account=None):
        with self.lock:
            if account is None:
                rows = self.db.execute('SELECT * FROM events ORDER BY timestamp')
            else:
                rows = self.db.execute('SELECT * FROM events WHERE account = ? ORDER BY timestamp', (account,))
            return [dict(row) for row in rows]

    def clear(self):
        with self.lock, self.db:
            self.db.execute('DELETE FROM events')

    def close(self):
        self.db.close()
