    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from samba.ini
    class TestSambaRules(unittest.TestCase):
            def test_samba_denied_connect(self) -> None:
            log = '''Dec 18 18:06:28 hostname smbd[832]: Denied connection from (192.168.3.23)'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'smbd')
            self.assertEqual(response.rule_id, '13102')
            self.assertEqual(response.alert_level, 5)

            def test_samba_connect_denied(self) -> None:
            log = '''Dec 18 18:06:28 hostname smbd[832]: Denied connection from (192.168.3.23)'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'smbd')
            self.assertEqual(response.rule_id, '13102')
            self.assertEqual(response.alert_level, 5)

            def test_samba_permission_denied_1(self) -> None:
            log = '''Dec 18 18:06:28 hostname smbd[17535]: Permission denied user not allowed to delete,  pause, or resume print job. User name: ahmet. Printer name: prnq1.'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

                    def test_samba_permission_denied_2(self) -> None:
            log = '''Dec 18 18:06:28 hostname smbd[17535]: Permission denied\-\- user not allowed to delete,  pause, or resume print job. User name: ahmet. Printer name: prnq1.'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

            