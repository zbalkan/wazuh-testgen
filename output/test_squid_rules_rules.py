    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from squid_rules.ini
    class TestSquid_rulesRules(unittest.TestCase):
            def test_Squid_Bad_request_Invalid_syntax(self) -> None:
            log = '''1140701044.525   1231 192.168.1.201 TCP_DENIED/400 1536 GET ahmet - NONE/- text/html'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'squid-accesslog')
            self.assertEqual(response.rule_id, '35003')
            self.assertEqual(response.alert_level, 5)

            def test_Squid_Proxy_Authentication_Required(self) -> None:
            log = '''1140701230.827    781 192.168.1.210 TCP_DENIED/407 1785 GET http://www.ossec.net oahmet NONE/- text/html'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'squid-accesslog')
            self.assertEqual(response.rule_id, '35007')
            self.assertEqual(response.alert_level, 5)

    