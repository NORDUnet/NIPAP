import unittest

from .proxy_auth import ProxyAuthController
from ConfigParser import ConfigParser


class MockRequest():
    def __init__(self, remote_addr, headers={}, environ={}):
        self.remote_addr = remote_addr
        self.headers = headers
        self.environ = environ


class ProxyAuthControllerTest(unittest.TestCase):

    def setUp(self):
        self.controller = ProxyAuthController()
        self.req = MockRequest('127.0.0.1')

    def test_empty_config(self):
        cfg = ConfigParser()
        result = self.controller._proxy_auth_config(cfg, self.req)
        self.assertFalse(result['is_ready'])
        self.assertFalse(result['is_configured'])

    def test_no_auth(self):
        cfg = create_cfg()
        result = self.controller._proxy_auth_config(cfg, self.req)

        self.assertTrue(result['is_ready'])
        self.assertTrue(result['is_configured'])
        self.assertTrue(result['is_trusted'])
        self.assertIsNone(result['user'])
        self.assertEquals(result['full_name'], '')

    def test_header_successfull_auth_simple(self):
        cfg = create_cfg()
        self.req.headers = {
            'X-Remote-User': 'markus@nordu.net'
        }

        result = self.controller._proxy_auth_config(cfg, self.req)
        self.assertTrue(result['is_ready'])
        self.assertEquals(result['user'], 'markus@nordu.net')
        self.assertEquals(result['full_name'], '')

    def test_header_successfull_auth_full_rw(self):
        cfg = create_cfg({
            'header': 'AwesomeUserHeader',
            'trusted_proxies': '*',
            'full_name_header': 'FULLNAME',
            'rw_header': 'RW_GROUPS',
            'rw_split': ';',
            'rw_values': 'sei;npe',
        })

        req_rw = MockRequest('192.168.0.2', {
            'AwesomeUserHeader': 'markus',
            'FULLNAME': 'Markus Krogh',
            'RW_GROUPS': 'sei',
        })

        resp_rw = self.controller._proxy_auth_config(cfg, req_rw)

        self.assertTrue(resp_rw['is_ready'])
        self.assertTrue(resp_rw['is_configured'])
        self.assertTrue(resp_rw['is_trusted'])
        self.assertEquals(resp_rw['user'], 'markus')
        self.assertEquals(resp_rw['full_name'], 'Markus Krogh')
        self.assertFalse(resp_rw['is_readonly'])

    def test_header_successfull_auth_full_ro(self):
        cfg = create_cfg({
            'header': 'AwesomeUserHeader',
            'trusted_proxies': '*',
            'full_name_header': 'FULLNAME',
            'ro_header': 'RO_GROUPS',
            'ro_split': ',',
            'ro_values': 'manager,viewer',
        })
        req_ro = MockRequest('192.168.0.3', {
            'AwesomeUserHeader': 'jesper',
            'FULLNAME': 'Jesper',
            'RO_GROUPS': 'viewer,test',
        })

        resp_ro = self.controller._proxy_auth_config(cfg, req_ro)

        self.assertTrue(resp_ro['is_ready'])
        self.assertTrue(resp_ro['is_configured'])
        self.assertTrue(resp_ro['is_trusted'])
        self.assertEquals(resp_ro['user'], 'jesper')
        self.assertEquals(resp_ro['full_name'], 'Jesper')
        self.assertTrue(resp_ro['is_readonly'])

        req_rw = MockRequest('192.168.0.3', {
            'AwesomeUserHeader': 'editor',
            'FULLNAME': 'Editor',
            'RO_GROUPS': '',
        })
        resp_rw = self.controller._proxy_auth_config(cfg, req_rw)

        self.assertTrue(resp_rw['is_ready'])
        self.assertTrue(resp_rw['is_configured'])
        self.assertTrue(resp_rw['is_trusted'])
        self.assertEquals(resp_rw['user'], 'editor')
        self.assertEquals(resp_rw['full_name'], 'Editor')
        self.assertFalse(resp_rw['is_readonly'])

    def test_header_successfull_auth_full_ro_and_rw(self):
        cfg = create_cfg({
            'header': 'AwesomeUserHeader',
            'trusted_proxies': '*',
            'full_name_header': 'FULLNAME',
            'rw_header': 'RW_GROUPS',
            'rw_split': ';',
            'rw_values': 'sei;npe',
            'ro_header': 'RO_GROUPS',
            'ro_split': ',',
            'ro_values': 'manager,viewer',
        })
        req_ro = MockRequest('192.168.0.3', {
            'AwesomeUserHeader': 'htj',
            'FULLNAME': 'Henrik',
            'RW_GROUPS': 'sei',
            'RO_GROUPS': 'viewer',
        })

        resp_ro = self.controller._proxy_auth_config(cfg, req_ro)

        self.assertTrue(resp_ro['is_ready'])
        self.assertTrue(resp_ro['is_configured'])
        self.assertTrue(resp_ro['is_trusted'])
        self.assertEquals(resp_ro['user'], 'htj')
        self.assertFalse(resp_ro['is_readonly'])

    def test_environ_trusted(self):
        cfg = create_cfg({
            'header': 'REMOTE_USER',
        })
        req_rw = MockRequest('192.168.0.3', environ={
            'REMOTE_USER': 'htj',
        })

        resp_rw = self.controller._proxy_auth_config(cfg, req_rw)

        self.assertTrue(resp_rw['is_ready'])
        self.assertTrue(resp_rw['is_configured'])
        self.assertTrue(resp_rw['is_trusted'])
        self.assertEquals(resp_rw['user'], 'htj')
        self.assertFalse(resp_rw['is_readonly'])

    def test_environ_full(self):
        cfg = create_cfg({
            'header': 'REMOTE_USER',
            'trusted_proxies': '127.0.0.1',
            'full_name_header': 'FULLNAME',
            'rw_header': 'RW_GROUPS',
            'rw_split': ';',
            'rw_values': 'sei;npe',
            'ro_header': 'RO_GROUPS',
            'ro_split': ',',
            'ro_values': 'manager,viewer',
        })
        req_rw = MockRequest('192.168.0.3', environ={
            'REMOTE_USER': 'htj',
            'FULLNAME': 'Henrik',
            'RW_GROUPS': 'viewer',
            'RO_GROUPS': 'viewer',
        })

        resp_rw = self.controller._proxy_auth_config(cfg, req_rw)

        self.assertTrue(resp_rw['is_ready'])
        self.assertTrue(resp_rw['is_configured'])
        self.assertTrue(resp_rw['is_trusted'])
        self.assertEquals(resp_rw['user'], 'htj')
        self.assertEquals(resp_rw['full_name'], 'Henrik')
        self.assertTrue(resp_rw['is_readonly'])

    def test_environ_over_headers_default(self):
        cfg = create_cfg({
            'header': 'REMOTE_USER',
            'trusted_proxies': '127.0.0.1',
            'full_name_header': 'FULLNAME',
            'rw_header': 'RW_GROUPS',
            'rw_split': ';',
            'rw_values': 'sei;npe',
            'ro_header': 'RO_GROUPS',
            'ro_split': ',',
            'ro_values': 'manager,viewer',
        })
        req_rw = MockRequest('192.168.0.3', headers={
            'REMOTE_USER': 'htj',
            'FULLNAME': 'Henrik',
            'RW_GROUPS': 'viewer',
            'RO_GROUPS': 'viewer',
        },environ={
            'REMOTE_USER': 'htj-env',
            'FULLNAME': 'Henrik-env',
            'RW_GROUPS': 'viewer',
            'RO_GROUPS': 'viewer',
        })

        resp_rw = self.controller._proxy_auth_config(cfg, req_rw)

        self.assertTrue(resp_rw['is_ready'])
        self.assertTrue(resp_rw['is_configured'])
        self.assertTrue(resp_rw['is_trusted'])
        self.assertEquals(resp_rw['user'], 'htj-env')
        self.assertEquals(resp_rw['full_name'], 'Henrik-env')
        self.assertTrue(resp_rw['is_readonly'])


class ProxyIsReadOnly(unittest.TestCase):

    def setUp(self):
        self.controller = ProxyAuthController()
        self.is_readonly = self.controller._is_readonly

    def test_default_is_rw(self):
        is_ro, auth_failed = self.is_readonly()
        self.assertFalse(is_ro, 'nothing supplied should give RW')
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_rw_group_no_match_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['sei'], user_rw='')
        self.assertTrue(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_rw_group_match_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['sei'], user_rw='sei')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_rw_group_user_substr_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['sei'], user_rw='se')
        self.assertTrue(is_ro, 'user substring should not match')
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_rw_group_group_substr_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['se'], user_rw='sei')
        self.assertTrue(is_ro, 'group substring should not match')
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_ro_group_no_match_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(ro_allowed=['sei'])
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_ro_group_match_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(ro_allowed=['sei'], user_ro='sei')
        self.assertTrue(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_ro_group_user_substr_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(ro_allowed=['dev'], user_ro='e')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_ro_group_group_substr_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(ro_allowed=['de'], user_ro='dev')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_ro_split_default_match_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(ro_allowed=['dev'], user_ro='dev sei')
        self.assertTrue(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_ro_split_match_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(ro_allowed=['dev'], user_ro='dev;sei', ro_split=';')
        self.assertTrue(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_rw_split_default_match_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['dev'], user_rw='dev sei')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_rw_split_match_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['dev'], user_rw='dev;sei', rw_split=';')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_both_rw_match_only_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='writer', user_ro='writer')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_both_both_match_should_be_rw(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='writer', user_ro='viewer')
        self.assertFalse(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_both_ro_match_should_be_ro(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='viewer', user_ro='viewer')
        self.assertTrue(is_ro)
        self.assertFalse(auth_failed, 'auth should not have failed')

    def test_both_no_matches_should_be_auth_failure(self):
        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='', user_ro='')
        self.assertTrue(auth_failed, 'no values should fail')

        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='manager', user_ro='manager')
        self.assertTrue(auth_failed, 'both no match should fail')

        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='manager', user_ro='')
        self.assertTrue(auth_failed, 'wrong rw and no ro should fail')

        is_ro, auth_failed = self.is_readonly(rw_allowed=['writer'], ro_allowed=['viewer'], user_rw='', user_ro='manager')
        self.assertTrue(auth_failed, 'no rw and wrong ro should fail')


def create_cfg(config={}):
    cfg = ConfigParser()
    cfg.add_section('auth.proxy')
    for k, v in config.items():
        cfg.set('auth.proxy', k, v)
    return cfg
