    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from vsftpd.ini
    class TestVsftpdRules(unittest.TestCase):
            def test_CONNECT_1(self) -> None:
            log = '''Wed Jul 27 18:32:27 2016 [pid 2] CONNECT: Client "fe80::baac:6fff:fe7d:d2e0"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'vsftpd')
            self.assertEqual(response.rule_id, '11401')
            self.assertEqual(response.alert_level, 3)

            def test_CONNECT_2(self) -> None:
            log = '''Wed Jul 27 18:32:27 2016 [pid 2] CONNECT: Client "10.11.12.13"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'vsftpd')
            self.assertEqual(response.rule_id, '11401')
            self.assertEqual(response.alert_level, 3)

            def test_LOGIN_1(self) -> None:
            log = '''Mon Oct 24 11:32:53 2016 [pid 1] [$ALOC$] FAIL LOGIN: Client "10.55.112.101"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'vsftpd')
            self.assertEqual(response.rule_id, '11403')
            self.assertEqual(response.alert_level, 5)

            def test_LOGIN_2(self) -> None:
            log = '''Mon Oct 24 11:32:53 2016 [pid 1] [$ALOC$] FAIL LOGIN: Client "fe80::baac:6fff:fe7d:d2e0"'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'vsftpd')
            self.assertEqual(response.rule_id, '11403')
            self.assertEqual(response.alert_level, 5)

    