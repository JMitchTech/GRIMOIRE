"""
utils/reader.py
Log reading module for Grimoire.
Reads live Windows Event Logs via pywin32 and .evtx files via python-evtx.

Requirements:
    pip install pywin32 python-evtx
    Run as Administrator for live log access.
"""

import os
import json
from datetime import datetime, timezone

# ── Windows Event IDs we care about ──────────────────────────────────────────
SECURITY_EVENT_IDS = {
    # Authentication
    4624: ('Successful Logon',          'info'),
    4625: ('Failed Logon',              'high'),
    4634: ('Logoff',                    'info'),
    4647: ('User Initiated Logoff',     'info'),
    4648: ('Logon with Explicit Creds', 'medium'),
    4672: ('Special Privileges Logon',  'medium'),
    4675: ('SIDs Filtered',             'low'),

    # Account Management
    4720: ('User Account Created',      'medium'),
    4722: ('User Account Enabled',      'low'),
    4723: ('Password Change Attempt',   'medium'),
    4724: ('Password Reset Attempt',    'medium'),
    4725: ('User Account Disabled',     'medium'),
    4726: ('User Account Deleted',      'high'),
    4728: ('Member Added to Global Group',   'medium'),
    4732: ('Member Added to Local Group',    'medium'),
    4756: ('Member Added to Universal Group','medium'),
    4740: ('Account Locked Out',        'high'),
    4767: ('Account Unlocked',          'low'),

    # Privilege / Escalation
    4673: ('Privileged Service Called', 'medium'),
    4674: ('Operation on Privileged Object', 'medium'),
    4688: ('Process Created',           'low'),
    4689: ('Process Exited',            'info'),
    4697: ('Service Installed',         'high'),

    # Policy / Audit
    4713: ('Kerberos Policy Changed',   'high'),
    4719: ('Audit Policy Changed',      'high'),
    4739: ('Domain Policy Changed',     'high'),

    # Logon Types
    4776: ('Credential Validation',     'low'),
    4777: ('Credential Validation Failed', 'high'),
}

SYSTEM_EVENT_IDS = {
    7034: ('Service Crashed',           'high'),
    7035: ('Service Control Request',   'low'),
    7036: ('Service State Changed',     'low'),
    7040: ('Service Start Type Changed','medium'),
    7045: ('New Service Installed',     'high'),
    1074: ('System Shutdown/Restart',   'medium'),
    6005: ('Event Log Service Started', 'low'),
    6006: ('Event Log Service Stopped', 'medium'),
    6008: ('Unexpected Shutdown',       'high'),
}

APPLICATION_EVENT_IDS = {
    1000: ('Application Error',         'medium'),
    1001: ('Application Fault',         'medium'),
    1002: ('Application Hang',          'low'),
}

ALL_EVENT_IDS = {**SECURITY_EVENT_IDS, **SYSTEM_EVENT_IDS, **APPLICATION_EVENT_IDS}

LOGON_TYPES = {
    2:  'Interactive',
    3:  'Network',
    4:  'Batch',
    5:  'Service',
    7:  'Unlock',
    8:  'NetworkCleartext',
    9:  'NewCredentials',
    10: 'RemoteInteractive',
    11: 'CachedInteractive',
}


def _format_event(event_id: int, time_str: str, source: str,
                  message: str, level: str) -> dict:
    """Build a standardized event dict."""
    info = ALL_EVENT_IDS.get(event_id, ('Unknown Event', 'info'))
    return {
        'event_id':   event_id,
        'name':       info[0],
        'severity':   info[1] if level == 'auto' else level,
        'timestamp':  time_str,
        'source':     source,
        'message':    message[:300],  # truncate for transport
        'raw':        message[:1000],
    }


def read_live_logs(log_type: str = 'Security', max_events: int = 500) -> list:
    """
    Read live Windows Event Logs using pywin32.

    Args:
        log_type:   'Security', 'System', or 'Application'
        max_events: Maximum number of events to return

    Returns:
        List of event dicts
    """
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import pywintypes
    except ImportError:
        raise RuntimeError(
            'pywin32 is not installed. Run: pip install pywin32\n'
            'Also run: python Scripts/pywin32_postinstall.py -install'
        )

    events   = []
    hand     = win32evtlog.OpenEventLog(None, log_type)
    flags    = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
    total    = win32evtlog.GetNumberOfEventLogRecords(hand)

    try:
        while len(events) < max_events:
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not raw_events:
                break
            for ev in raw_events:
                if len(events) >= max_events:
                    break
                event_id = ev.EventID & 0xFFFF
                if event_id not in ALL_EVENT_IDS and log_type == 'Security':
                    continue

                try:
                    msg = win32evtlogutil.SafeFormatMessage(ev, log_type)
                except Exception:
                    msg = str(ev.StringInserts) if ev.StringInserts else ''

                time_str = ev.TimeGenerated.Format('%Y-%m-%d %H:%M:%S')
                level    = _level_from_type(ev.EventType)
                source   = str(ev.SourceName)

                events.append(_format_event(event_id, time_str, source, msg, level))
    finally:
        win32evtlog.CloseEventLog(hand)

    return events


def read_evtx_file(filepath: str) -> list:
    """
    Parse an .evtx file using python-evtx.

    Args:
        filepath: Path to the .evtx file

    Returns:
        List of event dicts
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        import xml.etree.ElementTree as ET
    except ImportError:
        raise RuntimeError(
            'python-evtx is not installed. Run: pip install python-evtx'
        )

    events = []

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root    = ET.fromstring(xml_str)
                ns      = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                sys_node  = root.find('e:System', ns)
                event_id  = int(sys_node.find('e:EventID', ns).text)
                time_str  = sys_node.find('e:TimeCreated', ns).get('SystemTime', '')[:19].replace('T', ' ')
                source    = sys_node.find('e:Provider', ns).get('Name', 'Unknown')
                level_raw = sys_node.find('e:Level', ns)
                level_num = int(level_raw.text) if level_raw is not None and level_raw.text else 4

                level  = _level_from_num(level_num)
                msg    = xml_str[:500]

                # Try to extract EventData fields
                data_node = root.find('e:EventData', ns)
                if data_node is not None:
                    fields = {
                        d.get('Name', ''): (d.text or '')
                        for d in data_node.findall('e:Data', ns)
                    }
                    msg = json.dumps(fields)

                events.append(_format_event(event_id, time_str, source, msg, level))

            except Exception:
                continue

    return events


def _level_from_type(event_type: int) -> str:
    """Convert win32 event type to severity string."""
    mapping = {
        1: 'high',    # EVENTLOG_ERROR_TYPE
        2: 'medium',  # EVENTLOG_WARNING_TYPE
        4: 'info',    # EVENTLOG_INFORMATION_TYPE
        8: 'low',     # EVENTLOG_AUDIT_SUCCESS
        16: 'high',   # EVENTLOG_AUDIT_FAILURE
    }
    return mapping.get(event_type, 'info')


def _level_from_num(level: int) -> str:
    """Convert evtx level number to severity string."""
    mapping = {
        1: 'high',    # Critical
        2: 'high',    # Error
        3: 'medium',  # Warning
        4: 'info',    # Information
        5: 'low',     # Verbose
    }
    return mapping.get(level, 'info')
