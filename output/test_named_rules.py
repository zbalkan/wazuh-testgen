    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from named.ini
    class TestNamedRules(unittest.TestCase):
            def test_Query_cache_denied_1(self) -> None:
            log = '''Aug 29 15:33:13 ns3 named[464]: client 217.148.39.3#1036: query (cache) denied'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'named')
            self.assertEqual(response.rule_id, '12108')
            self.assertEqual(response.alert_level, 5)

            def test_Query_cache_denied_2(self) -> None:
            log = '''Aug 29 15:33:13 ns3 named[464]: client 217.148.39.4#32769: query (cache) denied'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'named')
            self.assertEqual(response.rule_id, '12108')
            self.assertEqual(response.alert_level, 5)

            def test_Query_cache_denied_3(self) -> None:
            log = '''Aug 29 15:33:13 ns3 named[464]: client 217.148.39.3#1036: query (cache) denied'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'named')
            self.assertEqual(response.rule_id, '12108')
            self.assertEqual(response.alert_level, 5)

            def test_Query_cache_denied_4(self) -> None:
            log = '''Aug 29 15:33:13 ns3 name[464]: client 217.148.39.4#32769: query (cache) denied'''
            response = send_log(log)

            self.assertNotEqual(response.status, LogtestStatus.RuleMatch)

                    def test_Query_cache_denied_5(self) -> None:
            log = '''Aug 29 15:33:13 ns3 named[464]: client 217.148.39.3#1036: query (cache)'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'named')
            self.assertEqual(response.rule_id, '12108')
            self.assertEqual(response.alert_level, 5)

    