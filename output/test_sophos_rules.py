    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from sophos.ini
    class TestSophosRules(unittest.TestCase):
            def test_sophos_win_Notice_message_detected(self) -> None:
            log = '''<log><category>savscan.log</category><level>INFO</level><domain>savscan</domain><msg>SAVSCAN-DETAILS %s %s %s %s %s %s</msg><time>1558570140</time><arg>0</arg><arg>0</arg><arg>108267</arg><arg>131</arg><arg>0</arg><arg>0</arg></log>'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos-win')
            self.assertEqual(response.rule_id, '64271')
            self.assertEqual(response.alert_level, 3)

            def test_sophos_win_NOTIFY_ONDEMANDTHREAT_INFECTED_alert(self) -> None:
            log = '''<log><category>savscan.log</category><level>INFO</level><domain>savscan</domain><msg>NOTIFY_ONDEMANDTHREAT_INFECTED %s</msg><time>1558572421</time><arg>path_file</arg></log>'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos-win')
            self.assertEqual(response.rule_id, '64272')
            self.assertEqual(response.alert_level, 6)

            def test_sophos_win_SCANNER_DIED_KILLED_alert(self) -> None:
            log = '''<log><category>savscan.log</category><level>INFO</level><domain>savscan</domain><msg>SCANNER_DIED_KILLED</msg><time>1558572421</time></log>'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos-win')
            self.assertEqual(response.rule_id, '64273')
            self.assertEqual(response.alert_level, 6)

            def test_sophos_win_NO_UPDATED_FROM_alert(self) -> None:
            log = '''<log><category>update.check</category><level>INFO</level><domain>savupdate</domain><msg>NO_UPDATED_FROM %s</msg><time>1558572421</time><arg>http://10.11.12.13/SophosUpdate/CIDs/S000/EESAVUNIX/SUNOS_9_SPARC</arg></log>'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos-win')
            self.assertEqual(response.rule_id, '64275')
            self.assertEqual(response.alert_level, 3)

            def test_sophos_cloud_scheduled_scan_started(self) -> None:
            log = '''20160806 050000	Scan 'Sophos Cloud Scheduled Scan' started.'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos')
            self.assertEqual(response.rule_id, '82101')
            self.assertEqual(response.alert_level, 3)

            def test_sophos_cloud_scheduled_scan_completed(self) -> None:
            log = '''20160806 052043	Scan 'Sophos Cloud Scheduled Scan' completed.'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos')
            self.assertEqual(response.rule_id, '82102')
            self.assertEqual(response.alert_level, 3)

            def test_sophos_av_on_access_scanning_stopped(self) -> None:
            log = '''20160805 175034	User (NT AUTHORITY\SYSTEM) has stopped on-access scanning for this machine.'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos')
            self.assertEqual(response.rule_id, '82104')
            self.assertEqual(response.alert_level, 3)

            def test_sophos_av_database_updated(self) -> None:
            log = '''20160805 175143	Using detection data version 5.29 (detection engine 3.65.2). This version can detect 11628132 items.'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'sophos')
            self.assertEqual(response.rule_id, '82105')
            self.assertEqual(response.alert_level, 3)

    