    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from mailscanner.ini
    class TestMailscannerRules(unittest.TestCase):
            def test_update_phishing(self) -> None:
            log = '''Feb 14 06:29:39 hostname update.bad.phishing.sites: Phishing bad sites list updated'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

            