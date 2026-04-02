"""
utils/analyzer.py
Threat analysis module for Grimoire.
Takes a list of parsed events and identifies patterns, anomalies, and threats.
"""

from collections import defaultdict, Counter
from datetime import datetime

# Thresholds for anomaly detection
BRUTE_FORCE_THRESHOLD   = 5    # failed logins from same source in window
LOCKOUT_THRESHOLD       = 3    # account lockouts in window
PRIV_ESC_THRESHOLD      = 3    # privilege escalation events in window
NEW_SERVICE_THRESHOLD   = 1    # any new service install is flagged


def analyze_events(events: list) -> dict:
    """
    Run full threat analysis on a list of parsed events.

    Returns:
        dict with summary stats, threats, top offenders, timeline data
    """
    threats        = []
    failed_logins  = defaultdict(list)   # {username: [timestamps]}
    locked_accounts = defaultdict(int)
    new_services   = []
    priv_events    = []
    account_changes = []
    policy_changes = []
    timeline       = defaultdict(int)    # {hour: count}
    severity_counts = Counter()
    event_id_counts = Counter()
    source_counts   = Counter()

    for ev in events:
        eid      = ev.get('event_id', 0)
        sev      = ev.get('severity', 'info')
        ts       = ev.get('timestamp', '')
        source   = ev.get('source', 'Unknown')
        msg      = ev.get('message', '')
        name     = ev.get('name', '')

        severity_counts[sev] += 1
        event_id_counts[eid] += 1
        source_counts[source] += 1

        # Timeline bucketing by hour
        try:
            dt   = datetime.strptime(ts[:13], '%Y-%m-%d %H')
            hour = dt.strftime('%m/%d %H:00')
            timeline[hour] += 1
        except Exception:
            pass

        # ── Failed logons (4625) ──────────────────────────────────────────
        if eid == 4625:
            username = _extract_field(msg, 'Account Name') or 'Unknown'
            failed_logins[username].append(ts)

        # ── Account lockouts (4740) ───────────────────────────────────────
        elif eid == 4740:
            username = _extract_field(msg, 'Account Name') or 'Unknown'
            locked_accounts[username] += 1
            threats.append({
                'severity': 'high',
                'type':     'Account Lockout',
                'detail':   f'Account "{username}" was locked out',
                'timestamp': ts,
                'event_id': eid,
            })

        # ── New service installed (7045, 4697) ───────────────────────────
        elif eid in (7045, 4697):
            svc_name = _extract_field(msg, 'Service Name') or 'Unknown Service'
            new_services.append(svc_name)
            threats.append({
                'severity': 'high',
                'type':     'New Service Installed',
                'detail':   f'Service "{svc_name}" was installed — verify legitimacy',
                'timestamp': ts,
                'event_id': eid,
            })

        # ── Privilege escalation (4672, 4673) ────────────────────────────
        elif eid in (4672, 4673):
            username = _extract_field(msg, 'Account Name') or 'Unknown'
            priv_events.append({'user': username, 'ts': ts})

        # ── Account management changes ────────────────────────────────────
        elif eid in (4720, 4726, 4728, 4732, 4756):
            username = _extract_field(msg, 'Account Name') or 'Unknown'
            account_changes.append({
                'severity': 'medium',
                'type':     name,
                'detail':   f'Account change: "{username}" — {name}',
                'timestamp': ts,
                'event_id': eid,
            })
            threats.append(account_changes[-1])

        # ── Policy changes ────────────────────────────────────────────────
        elif eid in (4719, 4739, 4713):
            policy_changes.append({
                'severity': 'high',
                'type':     'Policy Change',
                'detail':   f'{name} detected — review immediately',
                'timestamp': ts,
                'event_id': eid,
            })
            threats.append(policy_changes[-1])

        # ── Unexpected shutdown ───────────────────────────────────────────
        elif eid == 6008:
            threats.append({
                'severity': 'high',
                'type':     'Unexpected Shutdown',
                'detail':   'System experienced an unexpected shutdown or crash',
                'timestamp': ts,
                'event_id': eid,
            })

        # ── Audit policy cleared ──────────────────────────────────────────
        elif eid == 1102:
            threats.append({
                'severity': 'high',
                'type':     'Audit Log Cleared',
                'detail':   'Security audit log was cleared — possible cover-up attempt',
                'timestamp': ts,
                'event_id': eid,
            })

    # ── Brute force detection ─────────────────────────────────────────────────
    for username, timestamps in failed_logins.items():
        if len(timestamps) >= BRUTE_FORCE_THRESHOLD:
            threats.append({
                'severity': 'high',
                'type':     'Brute Force Detected',
                'detail':   f'{len(timestamps)} failed login attempts for "{username}"',
                'timestamp': timestamps[-1],
                'event_id': 4625,
            })

    # ── Privilege escalation pattern ──────────────────────────────────────────
    if len(priv_events) >= PRIV_ESC_THRESHOLD:
        users = list(set(e['user'] for e in priv_events))
        threats.append({
            'severity': 'medium',
            'type':     'Repeated Privilege Use',
            'detail':   f'{len(priv_events)} privilege escalation events — users: {", ".join(users[:3])}',
            'timestamp': priv_events[-1]['ts'],
            'event_id': 4672,
        })

    # ── Sort threats by severity ──────────────────────────────────────────────
    sev_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    threats.sort(key=lambda t: sev_order.get(t['severity'], 4))

    # ── Top event IDs ─────────────────────────────────────────────────────────
    top_events = [
        {'event_id': eid, 'count': cnt, 'name': _id_name(eid)}
        for eid, cnt in event_id_counts.most_common(10)
    ]

    # ── Top sources ───────────────────────────────────────────────────────────
    top_sources = [
        {'source': src, 'count': cnt}
        for src, cnt in source_counts.most_common(5)
    ]

    # ── Timeline (sorted) ─────────────────────────────────────────────────────
    sorted_timeline = [
        {'hour': h, 'count': c}
        for h, c in sorted(timeline.items())
    ]

    return {
        'total_events':   len(events),
        'threat_count':   len(threats),
        'severity_counts': dict(severity_counts),
        'threats':        threats[:50],   # cap at 50 for display
        'top_events':     top_events,
        'top_sources':    top_sources,
        'timeline':       sorted_timeline,
        'failed_logins':  {u: len(t) for u, t in failed_logins.items()},
        'locked_accounts': dict(locked_accounts),
        'new_services':   new_services,
    }


def _extract_field(message: str, field: str) -> str:
    """Try to extract a named field from a log message string."""
    try:
        # Handle JSON formatted messages from evtx parser
        import json
        data = json.loads(message)
        for key, val in data.items():
            if field.lower() in key.lower():
                return str(val).strip()
    except Exception:
        pass

    # Fallback: simple line-by-line search
    for line in message.splitlines():
        if field.lower() in line.lower() and ':' in line:
            return line.split(':', 1)[-1].strip()
    return ''


def _id_name(event_id: int) -> str:
    """Return friendly name for a known event ID."""
    from utils.reader import ALL_EVENT_IDS
    return ALL_EVENT_IDS.get(event_id, ('Unknown',))[0]
