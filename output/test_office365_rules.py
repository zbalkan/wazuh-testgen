    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from office365.ini
    class TestOffice365Rules(unittest.TestCase):
            def test_Office_365_GenericRule(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Rule","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91532')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ExchangeAdmin(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ExchangeAdmin","IntraSystemId":"sanitized","RecordType":"1","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91533')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ExchangeItem(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ExchangeItem","IntraSystemId":"sanitized","RecordType":"2","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91534')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ExchangeItemGroup(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ExchangeItemGroup","IntraSystemId":"sanitized","RecordType":"3","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91535')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePoint(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePoint","IntraSystemId":"sanitized","RecordType":"4","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91536')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointFileOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointFileOperation","IntraSystemId":"sanitized","RecordType":"6","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91537')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_OneDrive(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"OneDrive","IntraSystemId":"sanitized","RecordType":"7","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91538')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AzureActiveDirectory(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AzureActiveDirectory","IntraSystemId":"sanitized","RecordType":"8","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91539')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AzureActiveDirectoryAccountLogon(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AzureActiveDirectoryAccountLogon","IntraSystemId":"sanitized","RecordType":"9","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91540')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_DataCenterSecurityCmdlet(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"DataCenterSecurityCmdlet","IntraSystemId":"sanitized","RecordType":"10","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91541')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ComplianceDLPSharePoint(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ComplianceDLPSharePoint","IntraSystemId":"sanitized","RecordType":"11","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91542')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ComplianceDLPExchange(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ComplianceDLPExchange","IntraSystemId":"sanitized","RecordType":"13","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91543')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointSharingOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointSharingOperation","IntraSystemId":"sanitized","RecordType":"14","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91544')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AzureActiveDirectoryStsLogon(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AzureActiveDirectoryStsLogon","IntraSystemId":"sanitized","RecordType":"15","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91545')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SkypeForBusinessPSTNUsage(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SkypeForBusinessPSTNUsage","IntraSystemId":"sanitized","RecordType":"16","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91546')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SkypeForBusinessUsersBlocked(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SkypeForBusinessUsersBlocked","IntraSystemId":"sanitized","RecordType":"17","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91547')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_SecurityComplianceCenterEOPCmdlet(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SecurityComplianceCenterEOPCmdlet","IntraSystemId":"sanitized","RecordType":"18","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91548')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_ExchangeAggregatedOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ExchangeAggregatedOperation","IntraSystemId":"sanitized","RecordType":"19","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91549')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_PowerBIAudit(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"PowerBIAudit","IntraSystemId":"sanitized","RecordType":"20","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91550')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_CRM(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"CRM","IntraSystemId":"sanitized","RecordType":"21","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91551')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_Yammer(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Yammer","IntraSystemId":"sanitized","RecordType":"22","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91552')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SkypeForBusinessCmdlets(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SkypeForBusinessCmdlets","IntraSystemId":"sanitized","RecordType":"23","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91553')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_Discovery(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Discovery","IntraSystemId":"sanitized","RecordType":"24","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91554')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_MicrosoftTeams(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftTeams","IntraSystemId":"sanitized","RecordType":"25","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91555')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ThreatIntelligence(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ThreatIntelligence","IntraSystemId":"sanitized","RecordType":"28","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91556')
            self.assertEqual(response.alert_level, 12)

            def test_Office_365_MailSubmission(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MailSubmission","IntraSystemId":"sanitized","RecordType":"29","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91557')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_MicrosoftFlow(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftFlow","IntraSystemId":"sanitized","RecordType":"30","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91558')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AeD(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AeD","IntraSystemId":"sanitized","RecordType":"31","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91559')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MicrosoftStream(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftStream","IntraSystemId":"sanitized","RecordType":"32","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91560')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ComplianceDLPSharePointClassification(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ComplianceDLPSharePointClassification","IntraSystemId":"sanitized","RecordType":"33","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91561')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ThreatFinder(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ThreatFinder","IntraSystemId":"sanitized","RecordType":"34","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91562')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_Project(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Project","IntraSystemId":"sanitized","RecordType":"35","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91563')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointListOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointListOperation","IntraSystemId":"sanitized","RecordType":"36","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91564')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointCommentOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointCommentOperation","IntraSystemId":"sanitized","RecordType":"37","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91565')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_DataGovernance(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"DataGovernance","IntraSystemId":"sanitized","RecordType":"38","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91566')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_Kaizala(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Kaizala","IntraSystemId":"sanitized","RecordType":"39","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91567')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SecurityComplianceAlerts(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SecurityComplianceAlerts","IntraSystemId":"sanitized","RecordType":"40","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91568')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_ThreatIntelligenceUrl(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ThreatIntelligenceUrl","IntraSystemId":"sanitized","RecordType":"41","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91569')
            self.assertEqual(response.alert_level, 7)

            def test_Office_365_SecurityComplianceInsights(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SecurityComplianceInsights","IntraSystemId":"sanitized","RecordType":"42","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91570')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_MIPLabel(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MIPLabel","IntraSystemId":"sanitized","RecordType":"43","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91571')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_WorkplaceAnalytics(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"WorkplaceAnalytics","IntraSystemId":"sanitized","RecordType":"44","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91572')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_PowerAppsApp(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"PowerAppsApp","IntraSystemId":"sanitized","RecordType":"45","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91573')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_PowerAppsPlan(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"PowerAppsPlan","IntraSystemId":"sanitized","RecordType":"46","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91574')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ThreatIntelligenceAtpContent(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ThreatIntelligenceAtpContent","IntraSystemId":"sanitized","RecordType":"47","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91575')
            self.assertEqual(response.alert_level, 12)

            def test_Office_365_LabelContentExplorer(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"LabelContentExplorer","IntraSystemId":"sanitized","RecordType":"48","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91576')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_TeamsHealthcare(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"TeamsHealthcare","IntraSystemId":"sanitized","RecordType":"49","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91577')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ExchangeItemAggregated(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ExchangeItemAggregated","IntraSystemId":"sanitized","RecordType":"50","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91578')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_HygieneEvent(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"HygieneEvent","IntraSystemId":"sanitized","RecordType":"51","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91579')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_DataInsightsRestApiAudit(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"DataInsightsRestApiAudit","IntraSystemId":"sanitized","RecordType":"52","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91580')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_InformationBarrierPolicyApplication(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"InformationBarrierPolicyApplication","IntraSystemId":"sanitized","RecordType":"53","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91581')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointListItemOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointListItemOperation","IntraSystemId":"sanitized","RecordType":"54","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91582')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointContentTypeOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointContentTypeOperation","IntraSystemId":"sanitized","RecordType":"55","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91583')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointFieldOperation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointFieldOperation","IntraSystemId":"sanitized","RecordType":"56","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91584')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MicrosoftTeamsAdmin(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftTeamsAdmin","IntraSystemId":"sanitized","RecordType":"57","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91585')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_HRSignal(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"HRSignal","IntraSystemId":"sanitized","RecordType":"58","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91586')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MicrosoftTeamsDevice(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftTeamsDevice","IntraSystemId":"sanitized","RecordType":"59","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91587')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MicrosoftTeamsAnalytics(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftTeamsAnalytics","IntraSystemId":"sanitized","RecordType":"60","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91588')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_InformationWorkerProtection(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"InformationWorkerProtection","IntraSystemId":"sanitized","RecordType":"61","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91589')
            self.assertEqual(response.alert_level, 7)

            def test_Office_365_Campaign(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Campaign","IntraSystemId":"sanitized","RecordType":"62","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91590')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_DLPEndpoint(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"DLPEndpoint","IntraSystemId":"sanitized","RecordType":"63","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91591')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AirInvestigation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AirInvestigation","IntraSystemId":"sanitized","RecordType":"64","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91592')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_Quarantine(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Quarantine","IntraSystemId":"sanitized","RecordType":"65","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91593')
            self.assertEqual(response.alert_level, 9)

            def test_Office_365_MicrosoftForms(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftForms","IntraSystemId":"sanitized","RecordType":"66","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91594')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ApplicationAudit(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ApplicationAudit","IntraSystemId":"sanitized","RecordType":"67","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91595')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_ComplianceSupervisionExchange(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ComplianceSupervisionExchange","IntraSystemId":"sanitized","RecordType":"68","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91596')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_CustomerKeyServiceEncryption(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"CustomerKeyServiceEncryption","IntraSystemId":"sanitized","RecordType":"69","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91597')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_OfficeNative(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"OfficeNative","IntraSystemId":"sanitized","RecordType":"70","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91598')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_MipAutoLabelSharePointItem(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MipAutoLabelSharePointItem","IntraSystemId":"sanitized","RecordType":"71","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91599')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MipAutoLabelSharePointPolicyLocation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MipAutoLabelSharePointPolicyLocation","IntraSystemId":"sanitized","RecordType":"72","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91600')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MicrosoftTeamsShifts(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MicrosoftTeamsShifts","IntraSystemId":"sanitized","RecordType":"73","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91601')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MipAutoLabelExchangeItem(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MipAutoLabelExchangeItem","IntraSystemId":"sanitized","RecordType":"75","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91602')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_CortanaBriefing(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"CortanaBriefing","IntraSystemId":"sanitized","RecordType":"76","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91603')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_Search(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Search","IntraSystemId":"sanitized","RecordType":"77","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91604')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_WDATPAlerts(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"WDATPAlerts","IntraSystemId":"sanitized","RecordType":"78","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91605')
            self.assertEqual(response.alert_level, 7)

            def test_Office_365_MDATPAudit(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MDATPAudit","IntraSystemId":"sanitized","RecordType":"81","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91606')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_SensitivityLabelPolicyMatch(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SensitivityLabelPolicyMatch","IntraSystemId":"sanitized","RecordType":"82","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91607')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_SensitivityLabelAction(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SensitivityLabelAction","IntraSystemId":"sanitized","RecordType":"83","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91608')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_SensitivityLabeledFileAction(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SensitivityLabeledFileAction","IntraSystemId":"sanitized","RecordType":"84","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91609')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_AttackSim(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AttackSim","IntraSystemId":"sanitized","RecordType":"85","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91610')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AirManualInvestigation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AirManualInvestigation","IntraSystemId":"sanitized","RecordType":"86","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91611')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_SecurityComplianceRBAC(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SecurityComplianceRBAC","IntraSystemId":"sanitized","RecordType":"87","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91612')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_UserTraining(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"UserTraining","IntraSystemId":"sanitized","RecordType":"88","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91613')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AirAdminActionInvestigation(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AirAdminActionInvestigation","IntraSystemId":"sanitized","RecordType":"89","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91614')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_MSTIC(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MSTIC","IntraSystemId":"sanitized","RecordType":"90","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91615')
            self.assertEqual(response.alert_level, 7)

            def test_Office_365_PhysicalBadgingSignal(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"PhysicalBadgingSignal","IntraSystemId":"sanitized","RecordType":"91","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91616')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_AipDiscover(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AipDiscover","IntraSystemId":"sanitized","RecordType":"93","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91617')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_AipSensitivityLabelAction(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AipSensitivityLabelAction","IntraSystemId":"sanitized","RecordType":"94","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91618')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_AipProtectionAction(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AipProtectionAction","IntraSystemId":"sanitized","RecordType":"95","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91619')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_AipFileDeleted(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AipFileDeleted","IntraSystemId":"sanitized","RecordType":"96","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91620')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_AipHeartBeat(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"AipHeartBeat","IntraSystemId":"sanitized","RecordType":"97","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91621')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MCASAlerts(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MCASAlerts","IntraSystemId":"sanitized","RecordType":"98","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91622')
            self.assertEqual(response.alert_level, 7)

            def test_Office_365_OnPremisesFileShareScannerDlp(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"OnPremisesFileShareScannerDlp","IntraSystemId":"sanitized","RecordType":"99","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91623')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_OnPremisesSharePointScannerDlp(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"OnPremisesSharePointScannerDlp","IntraSystemId":"sanitized","RecordType":"100","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91624')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_ExchangeSearch(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ExchangeSearch","IntraSystemId":"sanitized","RecordType":"101","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91625')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SharePointSearch(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SharePointSearch","IntraSystemId":"sanitized","RecordType":"102","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91626')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_PrivacyInsights(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"PrivacyInsights","IntraSystemId":"sanitized","RecordType":"103","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91627')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MyAnalyticsSettings(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MyAnalyticsSettings","IntraSystemId":"sanitized","RecordType":"105","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91628')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_SecurityComplianceUserChange(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"SecurityComplianceUserChange","IntraSystemId":"sanitized","RecordType":"106","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91629')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_ComplianceDLPExchangeClassification(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"ComplianceDLPExchangeClassification","IntraSystemId":"sanitized","RecordType":"107","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91630')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_MipExactDataMatch(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"MipExactDataMatch","IntraSystemId":"sanitized","RecordType":"109","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91631')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_module_internal_event_3_request_fail(self) -> None:
            log = '''{"integration":"office365","office365":{"actor":"wazuh","tenant_id":"8CE4AF1D-20DC-4E7E-B306-1CEF89A3B898","subscription_name":"Audit.Exchange"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91648')
            self.assertEqual(response.alert_level, 3)

            def test_Office_365_FileMalwareDetected(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"FileMalwareDetected","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91700')
            self.assertEqual(response.alert_level, 14)

            def test_Office_365_FileMalwareDetected_Priority(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"FileMalwareDetected","IntraSystemId":"sanitized","RecordType":"6","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91700')
            self.assertEqual(response.alert_level, 14)

            def test_Office_365_DocumentSensitivityMismatchDetected(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"DocumentSensitivityMismatchDetected","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91701')
            self.assertEqual(response.alert_level, 5)

            def test_Office_365_FileDownloaded(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"FileDownloaded","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91702')
            self.assertEqual(response.alert_level, 4)

            def test_Office_365_PermissionLevelAdded(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"PermissionLevelAdded","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91703')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_SharingInvitationBlocked(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"SharingInvitationBlocked","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91704')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Add_MailboxPermission(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add-MailboxPermission","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91705')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_AddFolderPermissions(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"AddFolderPermissions","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91706')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Send(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Send","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91707')
            self.assertEqual(response.alert_level, 4)

            def test_Office_365_SendAs(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"SendAs","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91708')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_SendOnBehalf(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"SendOnBehalf","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91708')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Add_user(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add user.","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91709')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Update_user(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Update user.","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91710')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Add_member_to_role(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add member to role.","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91711')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Add_group(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add group.","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91712')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Add_member_to_group(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add member to group.","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91713')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_Add_service_principal_credentials(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add service principal credentials.","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91714')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_CaseAdminUpdated(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"CaseAdminUpdated","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91715')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_CaseAdminAdded(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"CaseAdminAdded","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91716')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_CaseAdded(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"CaseAdded","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91717')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_SearchCreated(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"SearchCreated","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91718')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_QuarantineDelete(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"QuarantineDelete","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91719')
            self.assertEqual(response.alert_level, 4)

            def test_Office_365_QuarantineExport(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"QuarantineExport","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91720')
            self.assertEqual(response.alert_level, 12)

            def test_Office_365_QuarantinePreview(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"QuarantinePreview","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91721')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_QuarantineRelease(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"QuarantineRelease","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91722')
            self.assertEqual(response.alert_level, 12)

            def test_Office_365_QuarantineViewHeader(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"QuarantineViewHeader","IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91723')
            self.assertEqual(response.alert_level, 6)

            def test_Office_365_FullAccessRight_Exchange(self) -> None:
            log = '''{"integration":"office365","office365":{"ObjectId":"sanitized","UserKey":"sanitized","ActorIpAddress":"sanitized","OrganizationId":"sanitized","ClientIP":"sanitized","Workload":"Generic","Operation":"Add-MailboxPermission","Parameters":[{"Name":"DomainController","Value":""},{"Name":"Identity","Value":"EURPR01A002.prod.outlook.com/Microsoft Exchange Hosted Organizations/testsiem.onmicrosoft.com/DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}"},{"Name":"User","Value":"EURPR01A002.prod.outlook.com/Microsoft Exchange Hosted Organizations/testsiem.onmicrosoft.com/Discovery Management"},{"Name":"AccessRights","Value":"FullAccess"}],"IntraSystemId":"sanitized","RecordType":"0","UserId":"wazuh@wazuh.com","CreationTime":"2020-03-19T16:48:02","Id":"sanitized","InterSystemsId":"sanitized","ApplicationId":"sanitized","ActorContextId":"sanitized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91725')
            self.assertEqual(response.alert_level, 10)

    