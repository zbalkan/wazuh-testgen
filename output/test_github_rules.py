    import unittest

    from internal.logtest import LogtestStatus, send_log


    # Converted from github.ini
    class TestGithubRules(unittest.TestCase):
            def test_GitHub_Account_Category(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"account."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91101')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Account_billing_plan_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"account.billing_plan_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91102')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Account_plan_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"account.plan_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91103')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Account_pending_plan_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"account.pending_plan_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91104')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Account_pending_subscription_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"account.pending_subscription_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91105')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Advisory_credit(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"advisory_credit."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91106')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Advisory_credit_accept(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"advisory_credit.accept"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91107')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Advisory_credit_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"advisory_credit.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91108')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Advisory_credit_decline(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"advisory_credit.decline"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91109')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Advisory_credit_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"advisory_credit.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91110')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Billing(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"billing."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91111')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Billing_change_billing_type(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"billing.change_billing_type"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91112')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Billing_change_billing_email(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"billing.change_billing_email"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91113')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Dependabot_alerts(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_alerts."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91114')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_alerts_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_alerts.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91115')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Dependabot_alerts_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_alerts.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91116')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_alerts_new_repos(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_alerts_new_repos."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91117')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_alerts_new_repos_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_alerts_new_repos.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91118')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Dependabot_alerts_new_repos_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_alerts_new_repos.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91119')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_security_updates(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_security_updates."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91120')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_security_updates_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_security_updates.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91121')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Dependabot_security_updates_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_security_updates.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91122')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_security_updates_new_repos(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_security_updates_new_repos."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91123')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependabot_security_updates_new_repos_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_security_updates_new_repos.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91124')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Dependabot_security_updates_new_repos_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependabot_security_updates_new_repos.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91125')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependency_graph(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependency_graph."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91126')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependency_graph_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependency_graph.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91127')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Dependency_graph_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependency_graph.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91128')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependency_graph_new_repos(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependency_graph_new_repos."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91129')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Dependency_graph_new_repos_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependency_graph_new_repos.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91130')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Dependency_graph_new_repos_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"dependency_graph_new_repos.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91131')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Discussion_post(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"discussion_post."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91132')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Discussion_post_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"discussion_post.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91133')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Discussion_post_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"discussion_post.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91134')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Discussion_post_reply(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"discussion_post_reply."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91135')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Discussion_post_replay_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"discussion_post_reply.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91136')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Discussion_post_replay_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"discussion_post_reply.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91137')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Enterprise(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91139')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Enterprise_Remove_self_hosted_runner(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.remove_self_hosted_runner"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91140')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Enterprise_Register_self_hosted_runner(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.register_self_hosted_runner"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91141')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Enterprise_Runner_group_created(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.runner_group_created"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91142')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Enterprise_Runner_group_removed(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.runner_group_removed"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91143')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Enterprise_Runner_group_runner_removed(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.runner_group_runner_removed"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91144')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Enterprise_Runner_group_runners_added(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.runner_group_runners_added"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91145')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Enterprise_Runner_group_runners_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.runner_group_runners_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91146')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Enterprise_Runner_group_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.runner_group_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91147')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Enterprise_Self_hosted_runner_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"enterprise.self_hosted_runner_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91148')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Environment(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91149')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Environment_Create_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.create_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91150')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Environment_Delete(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.delete"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91151')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Environment_Remove_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.remove_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91152')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Environment_Update_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.update_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91153')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Environment_Add_protection_rule(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.add_protection_rule"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91154')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Environment_Update_protection_rule(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.update_protection_rule"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91155')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Environment_Remove_protection_rule(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"environment.remove_protection_rule"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91156')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Git(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"git."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91157')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Git_clone(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"git.clone"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91158')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Git_fetch(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"git.fetch"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91159')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Git_push(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"git.push"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91160')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Hook(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"hook."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91161')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Hook_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"hook.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91162')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Hook_config_changed(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"hook.config_changed"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91163')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Hook_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"hook.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91164')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Hook_events_changed(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"hook.events_changed"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91165')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Integration_installation_1(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"integration_installation."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91166')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Integration_installation_2(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"integration_installation_request."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91166')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Integration_installation_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"integration_installation.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91167')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Integration_installation_close(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"integration_installation.close"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91168')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Issues_1(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"issue."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91169')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Issues_2(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"issues."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91169')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Issues_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"issues.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91170')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Marketplace_agreement_signature(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_agreement_signature."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91171')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Marketplace_agreement_signature_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_agreement_signature.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91172')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Marketplace_listing(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_listing."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91173')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Marketplace_listing_approve(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_listing.approve"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91174')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Marketplace_listing_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_listing.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91175')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Marketplace_listing_delist(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_listing.delist"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91176')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Marketplace_listing_redraft(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_listing.redraft"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91177')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Marketplace_listing_reject(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"marketplace_listing.reject"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91178')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Members_can_create_pages(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"members_can_create_pages."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91179')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Members_can_create_pages_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"members_can_create_pages.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91180')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Members_can_create_pages_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"members_can_create_pages.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91181')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Oauth_application(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"oauth_application."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91182')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Oauth_application_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"oauth_application.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91183')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Oauth_application_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"oauth_application.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91184')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Oauth_application_reset_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"oauth_application.reset_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91185')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Oauth_application_revoke_tokens(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"oauth_application.revoke_tokens"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91186')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Oauth_application_transfer(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"oauth_application.transfer"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91187')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91188')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_add_billing_manager(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.add_billing_manager"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91189')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_add_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.add_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91190')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_advanced_security_policy_selected_member_disabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.advanced_security_policy_selected_member_disabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91191')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_advanced_security_policy_selected_member_enabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.advanced_security_policy_selected_member_enabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91192')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_audit_log_export_1(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.audit_log_export"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91193')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_audit_log_export_2(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.audit_log_git_event_export"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91193')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_block_user(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.block_user"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91194')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_cancel_invitation(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.cancel_invitation"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91195')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91196')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_create_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.create_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91197')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_disable_member_team_creation_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.disable_member_team_creation_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91198')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_disable_oauth_app_restrictions(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.disable_oauth_app_restrictions"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91199')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Organization_disable_saml(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.disable_saml"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91200')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Organization_disable_two_factor_requirement(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.disable_two_factor_requirement"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91201')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Organization_display_commenter_full_name_enabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.display_commenter_full_name_enabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91202')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_enable_member_team_creation_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.enable_member_team_creation_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91203')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_enable_oauth_app_restrictions(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.enable_oauth_app_restrictions"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91204')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_enable_saml(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.enable_saml"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91205')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_enable_two_factor_requirement(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.enable_two_factor_requirement"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91206')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_invite_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.invite_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91207')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_oauth_app_access_approved(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.oauth_app_access_approved"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91208')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_oauth_app_access_denied(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.oauth_app_access_denied"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91209')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Organization_oauth_app_access_requested(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.oauth_app_access_requested"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91210')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_register_self_hosted_runner(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.register_self_hosted_runner"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91211')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_remove_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.remove_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91212')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_remove_billing_manager(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.remove_billing_manager"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91213')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_remove_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.remove_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91214')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_remove_outside_collaborator(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.remove_outside_collaborator"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91215')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_remove_self_hosted_runner(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.remove_self_hosted_runner"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91216')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_restore_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.restore_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91217')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_revoke_external_identity(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.revoke_external_identity"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91218')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_revoke_sso_session(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.revoke_sso_session"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91219')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_runner_group_created(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.runner_group_created"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91220')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_runner_group_removed(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.runner_group_removed"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91221')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_runner_group_runner_removed(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.runner_group_runner_removed"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91222')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_runner_group_runners_added(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.runner_group_runners_added"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91223')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_runner_group_runners_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.runner_group_runners_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91224')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_runner_group_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.runner_group_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91225')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_self_hosted_runner_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.self_hosted_runner_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91226')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_set_actions_retention_limit(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.set_actions_retention_limit"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91227')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_unblock_user(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.unblock_user"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91228')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91229')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_actions_settings(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_actions_settings"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91230')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_default_repository_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_default_repository_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91231')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91232')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_update_member_repository_creation_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_member_repository_creation_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91233')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_new_repository_default_branch_setting(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_new_repository_default_branch_setting"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91234')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_saml_provider_settings(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_saml_provider_settings"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91235')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_update_terms_of_service(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org.update_terms_of_service"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91236')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_credential_authorization(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org_credential_authorization."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91239')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_credential_authorization_grant(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org_credential_authorization.grant"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91240')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Organization_credential_authorization_deauthorized(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org_credential_authorization.deauthorized"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91241')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Organization_credential_authorization_revoke(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"org_credential_authorization.revoke"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91242')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Organization_default_label_1(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_default_label."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91243')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_default_label_2(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_label."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91243')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_default_label_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_default_label.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91244')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_default_label_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_default_label.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91245')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_default_label_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_default_label.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91246')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Packages(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"packages."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91247')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Package_version_published(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"packages.package_version_published"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91248')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Package_version_deleted(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"packages.package_version_deleted"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91249')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Package_deleted(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"packages.package_deleted"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91250')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Package_version_restored(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"packages.package_version_restored"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91251')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Package_restored(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"packages.package_restored"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91252')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Payment_method(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"payment_method."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91253')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Payment_method_clear(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"payment_method.clear"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91254')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Payment_method_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"payment_method.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91255')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Payment_method_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"payment_method.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91256')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Profile_picture(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"profile_picture."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91257')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Profile_picture_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"profile_picture.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91258')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91259')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Project_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91260')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project_link(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.link"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91261')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project_rename(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.rename"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91262')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91263')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project_delete(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.delete"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91264')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Project_unlink(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.unlink"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91265')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Project_update_org_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.update_org_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91266')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project_update_team_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.update_team_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91267')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Project_update_user_permission(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"project.update_user_permission"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91268')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_domain(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_domain."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91269')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Organization_domain_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_domain.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91270')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Organization_domain_delete(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"organization_domain.delete"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91271')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Private_repository_forking(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"private_repository_forking."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91272')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Private_repository_forking_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"private_repository_forking.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91273')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Private_repository_forking_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"private_repository_forking.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91274')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91275')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Protected_branch_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91276')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91277')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Protected_branch_update_admin_enforced(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_admin_enforced"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91278')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_require_code_owner_review(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_require_code_owner_review"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91279')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_dismissal_restricted_users_teams(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.dismissal_restricted_users_teams"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91280')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_dismiss_stale_reviews(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.dismiss_stale_reviews"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91281')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_signature_requirement_enforcement_level(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_signature_requirement_enforcement_level"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91282')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_pull_request_reviews_enforcement_level(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_pull_request_reviews_enforcement_level"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91283')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_required_status_checks_enforcement_level(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_required_status_checks_enforcement_level"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91284')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_strict_required_status_checks_policy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_strict_required_status_checks_policy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91285')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_rejected_ref_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.rejected_ref_update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91286')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_policy_override(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.policy_override"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91287')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_allow_force_pushes_enforcement_level(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_allow_force_pushes_enforcement_level"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91288')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_allow_deletions_enforcement_level(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_allow_deletions_enforcement_level"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91289')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Protected_branch_update_linear_history_requirement_enforcement_level(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"protected_branch.update_linear_history_requirement_enforcement_level"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91290')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91292')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Pull_request_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91293')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_close(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.close"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91294')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_reopen(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.reopen"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91295')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_merge(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.merge"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91296')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_indirect_merge(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.indirect_merge"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91297')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_ready_for_review(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.ready_for_review"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91298')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_converted_to_draft(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.converted_to_draft"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91299')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_create_review_request(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.create_review_request"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91300')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_remove_review_request(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request.remove_review_request"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91301')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_review(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91302')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Pull_request_review_submit(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review.submit"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91303')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_review_dismiss(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review.dismiss"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91304')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_review_delete(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review.delete"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91305')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_review_comment(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review_comment."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91306')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Pull_request_review_comment_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review_comment.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91307')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_review_comment_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review_comment.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91308')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Pull_request_review_comment_delete(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"pull_request_review_comment.delete"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91309')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91310')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repo_access(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.access"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91311')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repo_actions_enabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.actions_enabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91312')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_add_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.add_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91313')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_add_topic(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.add_topic"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91314')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_advanced_security_disabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.advanced_security_disabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91315')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Repo_advanced_security_enabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.advanced_security_enabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91316')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repo_archived(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.archived"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91317')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repo_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91318')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_create_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.create_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91319')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repo_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91320')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repo_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91321')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repo_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91322')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_pages_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.pages_create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91323')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_pages_https_redirect_enabled(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.pages_https_redirect_enabled"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91324')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_pages_private(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.pages_private"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91325')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_pages_public(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.pages_public"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91326')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_pages_source(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.pages_source"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91327')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_remove_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.remove_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91328')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repo_remove_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.remove_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91329')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repo_register_self_hosted_runner(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.register_self_hosted_runner"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91330')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repo_remove_self_hosted_runner(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.remove_self_hosted_runner"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91331')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repo_remove_topic(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.remove_topic"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91332')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_rename(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.rename"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91333')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_self_hosted_runner_updated(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.self_hosted_runner_updated"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91334')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repo_set_actions_retention_limit(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.set_actions_retention_limit"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91335')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_transfer(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.transfer"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91336')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_transfer_start(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.transfer_start"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91337')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_unarchived(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.unarchived"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91338')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repo_update_actions_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repo.update_actions_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91339')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_advisory(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91340')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_advisory_close(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.close"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91341')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_advisory_cve_request(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.cve_request"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91342')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_advisory_github_broadcast(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.github_broadcast"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91343')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_advisory_github_withdraw(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.github_withdraw"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91344')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_advisory_open(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.open"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91345')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_advisory_publish(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.publish"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91346')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_advisory_reopen(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.reopen"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91347')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_advisory_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_advisory.update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91348')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_content_analysis(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_content_analysis."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91349')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_content_analysis_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_content_analysis.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91350')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repository_content_analysis_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_content_analysis.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91351')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_dependency_graph(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_dependency_graph."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91352')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_dependency_graph_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_dependency_graph.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91353')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_dependency_graph_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_dependency_graph.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91354')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repository_projects_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_projects_change."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91355')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_projects_change_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_projects_change.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91356')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_projects_change_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_projects_change.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91357')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repository_secret_scanning(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_secret_scanning."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91358')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_secret_scanning_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_secret_scanning.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91359')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_secret_scanning_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_secret_scanning.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91360')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Repository_vulnerability_alert(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alert."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91361')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_vulnerability_alert_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alert.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91362')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Repository_vulnerability_alert_dismiss(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alert.dismiss"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91363')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Repository_vulnerability_alert_resolve(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alert.resolve"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91364')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_vulnerability_alerts(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alerts."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91365')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Repository_vulnerability_alerts_authorized_users_teams(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alerts.authorized_users_teams"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91366')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Repository_vulnerability_alerts_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alerts.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91367')
            self.assertEqual(response.alert_level, 12)

            def test_GitHub_Repository_vulnerability_alerts_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"repository_vulnerability_alerts.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91368')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Secret_scanning(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"secret_scanning."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91369')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Secret_scanning_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"secret_scanning.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91370')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Secret_scanning_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"secret_scanning.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91371')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Secret_scanning_new_repos(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"secret_scanning_new_repos."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91372')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Secret_scanning_new_repos_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"secret_scanning_new_repos.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91373')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Secret_scanning_new_repos_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"secret_scanning_new_repos.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91374')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91375')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Sponsors_custom_amount_settings_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.custom_amount_settings_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91376')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_repo_funding_links_file_action(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.repo_funding_links_file_action"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91377')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsorship_cancel(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsor_sponsorship_cancel"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91378')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsorship_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsor_sponsorship_create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91379')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsorship_preference_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsor_sponsorship_preference_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91380')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsorship_tier_change(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsor_sponsorship_tier_change"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91381')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_approve(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_approve"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91382')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91383')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91384')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_redraft(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_redraft"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91385')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_profile_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_profile_update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91386')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_request_approval(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_request_approval"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91387')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_tier_description_update(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_tier_description_update"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91388')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_sponsored_developer_update_newsletter_send(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.sponsored_developer_update_newsletter_send"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91389')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_waitlist_invite_sponsored_developer(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.waitlist_invite_sponsored_developer"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91390')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Sponsors_waitlist_join(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"sponsors.waitlist_join"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91391')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Team(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91392')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Team_add_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.add_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91393')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Team_add_repository(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.add_repository"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91394')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Team_change_parent_team(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.change_parent_team"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91395')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_change_privacy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.change_privacy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91396')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91397')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Team_demote_maintainer(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.demote_maintainer"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91398')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_destroy(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.destroy"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91399')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_promote_maintainer(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.promote_maintainer"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91400')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_remove_member(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.remove_member"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91401')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_remove_repository(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team.remove_repository"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91402')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Team_discussions(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team_discussions."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91403')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Team_discussions_disable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team_discussions.disable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91404')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Team_discussions_enable(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"team_discussions.enable"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91405')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Workflows(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91406')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Workflows_cancel_workflow_run(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.cancel_workflow_run"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91407')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_completed_workflow_run(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.completed_workflow_run"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91408')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_created_workflow_run(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.created_workflow_run"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91409')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_delete_workflow_run(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.delete_workflow_run"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91410')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_disable_workflow(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.disable_workflow"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91411')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_enable_workflow(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.enable_workflow"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91412')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_rerun_workflow_run(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.rerun_workflow_run"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91413')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Workflows_prepared_workflow_job(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"workflows.prepared_workflow_job"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91414')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Codespaces(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces."}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91415')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Codespaces_create(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.create"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91416')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Codespaces_resume(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.resume"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91417')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Codespaces_delete(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.delete"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91418')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Codespaces_create_an_org_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.create_an_org_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91419')
            self.assertEqual(response.alert_level, 5)

            def test_GitHub_Codespaces_update_an_org_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.update_an_org_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91420')
            self.assertEqual(response.alert_level, 7)

            def test_GitHub_Codespaces_remove_an_org_secret(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.remove_an_org_secret"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91421')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_Codespaces_manage_access_and_security(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"codespaces.manage_access_and_security"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91422')
            self.assertEqual(response.alert_level, 9)

            def test_GitHub_module_internal_event_3_request_fail(self) -> None:
            log = '''{"integration":"github","github":{"actor":"wazuh","created_at":1619032221869,"request":"request","response":"response"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91448')
            self.assertEqual(response.alert_level, 3)

            def test_GitHub_Generic_rule(self) -> None:
            log = '''{"integration":"github","github":{"actor":"user","org":"organization","created_at":1619032221869,"action":"unknown"}}'''
            response = send_log(log)

            self.assertEqual(response.status, LogtestStatus.RuleMatch)

            self.assertEqual(response.decoder, 'json')
            self.assertEqual(response.rule_id, '91449')
            self.assertEqual(response.alert_level, 3)

    