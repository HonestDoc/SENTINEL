# SENTINEL/ingestion/event_enricher.py
# Runs on: HOST Windows 11

class EventEnricher:
    """
    Takes a raw Windows event and adds context fields
    that behavioral models will use as features.
    """

    LOGON_TYPE_NAMES = {
        2: 'interactive',
        3: 'network',
        4: 'batch',
        5: 'service',
        7: 'unlock',
        8: 'network_cleartext',
        9: 'new_credentials',
        10: 'remote_interactive',
        11: 'cached_interactive'
    }

    LOLBINS = {
        'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
        'msiexec.exe', 'wmic.exe', 'cmstp.exe', 'installutil.exe',
        'regasm.exe', 'regsvcs.exe', 'odbcconf.exe', 'ieexec.exe',
        'msconfig.exe', 'wscript.exe', 'cscript.exe', 'msbuild.exe'
    }

    SUSPICIOUS_PARENTS = {
        ('winword.exe', 'cmd.exe'),
        ('excel.exe', 'cmd.exe'),
        ('outlook.exe', 'powershell.exe'),
        ('winword.exe', 'powershell.exe'),
        ('excel.exe', 'wscript.exe'),
    }

    def enrich(self, event):
        """Add context fields to a raw event dict"""
        enriched = event.copy()

        # Time context
        if 'hour' in event:
            enriched['is_after_hours'] = int(
                not (8 <= event['hour'] <= 18)
            )
            enriched['is_business_hours'] = int(8 <= event['hour'] <= 18)

        # Logon type name
        if 'logon_type' in event:
            enriched['logon_type_name'] = self.LOGON_TYPE_NAMES.get(
                event.get('logon_type'), 'unknown'
            )
            enriched['is_remote_logon'] = int(
                event.get('logon_type') in [3, 10]
            )

        # Process context
        process_name = event.get('process_name', '').lower()
        if process_name:
            enriched['is_lolbin'] = int(process_name in self.LOLBINS)
            enriched['is_from_temp'] = int(
                any(path in event.get('process_path', '').lower()
                    for path in ['\\temp\\', '\\appdata\\', '\\downloads\\'])
            )

        # Parent-child suspicious pair
        parent = event.get('parent_process', '').lower()
        child = event.get('process_name', '').lower()
        enriched['suspicious_parent_child'] = int(
            (parent, child) in self.SUSPICIOUS_PARENTS
        )

        # Authentication context
        enriched['is_failed_auth'] = int(
            event.get('event_id') == 4625
        )
        enriched['is_admin_logon'] = int(
            event.get('event_id') == 4672
        )

        return enriched

    def enrich_batch(self, events_list):
        return [self.enrich(e) for e in events_list]


if __name__ == '__main__':
    enricher = EventEnricher()

    test_events = [
        {
            'event_id': 4624,
            'process_name': 'certutil.exe',
            'parent_process': 'winword.exe',
            'hour': 2,
            'logon_type': 3,
            'process_path': 'C:\\Windows\\Temp\\certutil.exe'
        },
        {
            'event_id': 4624,
            'process_name': 'chrome.exe',
            'parent_process': 'explorer.exe',
            'hour': 10,
            'logon_type': 2,
            'process_path': 'C:\\Program Files\\Google\\Chrome\\chrome.exe'
        }
    ]

    for event in test_events:
        enriched = enricher.enrich(event)
        print(f"\nProcess: {event['process_name']}")
        print(f"  Is LOLBin:              {enriched['is_lolbin']}")
        print(f"  Is after hours:         {enriched['is_after_hours']}")
        print(f"  Suspicious parent/child:{enriched['suspicious_parent_child']}")
        print(f"  Is from temp:           {enriched['is_from_temp']}")
        print(f"  Is remote logon:        {enriched['is_remote_logon']}")