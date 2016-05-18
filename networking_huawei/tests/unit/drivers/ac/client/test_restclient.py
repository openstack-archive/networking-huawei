# Copyright (c) 2016 Huawei Technologies India Pvt Ltd
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
import requests

from oslo_config import cfg
from oslo_serialization import jsonutils
from oslotest import base

import networking_huawei.drivers.ac.client.restclient as ac_rest
from networking_huawei.drivers.ac.common import config  # noqa


test_create_network_req = {'network':
                           {'routerExternal': False,
                            'networkType': 'local',
                            'segmentationId': None,
                            'adminStateUp': True,
                            'tenant_id': 'test-tenant',
                            'name': 'net1',
                            'physicalNetwork': None,
                            'serviceName': 'physnet1',
                            'id': 'd897e21a-dfd6-4331-a5dd-7524fa421c3e',
                            'status': 'ACTIVE',
                            'shared': False}}


class HuaweiACRestClientTestCase(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.set_override('username', 'huawei_user', 'huawei_ac_config')
        cfg.CONF.set_override('password', 'huawei_pwd', 'huawei_ac_config')
        cfg.CONF.set_override('neutron_ip', '127.0.0.1', 'huawei_ac_config')
        cfg.CONF.set_override('neutron_name', 'NS_1', 'huawei_ac_config')

        super(HuaweiACRestClientTestCase, self).setUp()
        self.restc = ac_rest.RestClient
        self.host = cfg.CONF.huawei_ac_config.host
        self.port = cfg.CONF.huawei_ac_config.port
        self.url = '%s%s%s%s' % ("http://", self.host, ":", str(self.port))

    def _mock_req_resp(self, status_code):
        response = mock.Mock()
        response.response = "OK"
        response.status_code = status_code
        response.errorcode = 0
        response.content = jsonutils.dumps(
            {'result': "ok", 'errorCode': '0', 'errorMsg': None}, indent=2)
        return response

    def test_rc_send_timeout(self):
        methodname = 'POST'
        url = '/controller/dc/esdk/v2.0/test_url'
        expected_ret = {'errorCode': None, 'reason': None,
                        'response': None, 'status': -1}
        with mock.patch.object(self.restc, 'process_request',
                               return_value="Timeout Exceptions"):
            ret = ac_rest.RestClient().send(self.host, self.port,
                                            methodname, url, hex(10), {})
            self.assertEqual(expected_ret, ret, "Not expected return")

    def test_rc_send_success(self):
        methodname = 'POST'
        url = '/controller/dc/esdk/v2.0/test_url'
        expected_resp = {'errorCode': u'0', 'reason': None,
                         'response': 'ok', 'status': 204}
        with mock.patch.object(self.restc,
                               'process_request',
                               return_value=self._mock_req_resp
                               (requests.codes.no_content)):
            ret = ac_rest.RestClient().send(self.host, self.port,
                                            methodname, url,
                                            hex(10),
                                            test_create_network_req)
            self.assertEqual(expected_resp, ret, "Not expected response")

    def test_rc_send_del_network(self):
        methodname = 'DELETE'
        url = '/controller/dc/esdk/v2.0/test_url'
        expected_resp = {'errorCode': None, 'reason': None,
                         'response': None, 'status': 200}
        resp = self._mock_req_resp(requests.codes.ok)
        resp.content = ""
        with mock.patch.object(self.restc, 'process_request',
                               return_value=resp):
            ret = ac_rest.RestClient().send(self.host, self.port,
                                            methodname, url,
                                            hex(10),
                                            test_create_network_req)
            self.assertEqual(expected_resp, ret, "Not expected response")

    def test_rc_send_del_network_resp_valid(self):
        methodname = 'DELETE'
        url = '/controller/dc/esdk/v2.0/test_url'
        expected_resp = {'errorCode': None, 'reason': None,
                         'response': None, 'status': 300}
        resp = self._mock_req_resp(requests.codes.multiple_choices)
        with mock.patch.object(self.restc, 'process_request',
                               return_value=resp):
            ret = ac_rest.RestClient().send(self.host, self.port,
                                            methodname, url,
                                            hex(10),
                                            test_create_network_req)
            self.assertEqual(expected_resp, ret, "Not expected response")

    def test_rc_process_request(self):
        methodname = 'DELETE'
        url = '/controller/dc/esdk/v2.0/test_url'
        auth = (cfg.CONF.huawei_ac_config.username,
                cfg.CONF.huawei_ac_config.password)
        headers = {'Accept': 'application/json',
                   'Content-type': 'application/json'}
        data = {"network": {"routerExternal": False,
                            "id": "d897e21a-dfd6-4331-a5dd-7524fa421c3e",
                            "serviceName": "physnet1",
                            "status": "ACTIVE",
                            "shared": False,
                            "adminStateUp": True,
                            "tenant_id": "test-tenant",
                            "segmentationId": None,
                            "physicalNetwork": None,
                            "networkType": "local",
                            "name": "net1"}}
        resp = self._mock_req_resp(requests.codes.no_content)
        kwargs = {'url': url, 'data': data}
        with mock.patch('requests.request',
                        return_value=resp) as mock_method:
            ac_rest.RestClient().process_request(methodname, auth,
                                                 url, headers,
                                                 data)
            mock_method.\
                assert_called_once_with(
                    methodname,
                    headers={'Content-type':
                             'application/json',
                             'Accept':
                             'application/json'},
                    timeout=float(cfg.CONF.
                                  huawei_ac_config.
                                  request_timeout),
                    verify=False,
                    auth=(cfg.CONF.huawei_ac_config.username,
                          cfg.CONF.huawei_ac_config.password),
                    **kwargs)

    def test_rc_process_request_timeout_exception(self):
        methodname = 'DELETE'
        url = '/controller/dc/esdk/v2.0/test_url'
        auth = (cfg.CONF.huawei_ac_config.username,
                cfg.CONF.huawei_ac_config.password)
        headers = {'Accept': 'application/json',
                   'Content-type': 'application/json'}
        data = {"network": {"routerExternal": False,
                            "id": "d897e21a-dfd6-4331-a5dd-7524fa421c3e",
                            "serviceName": "physnet1",
                            "status": "ACTIVE",
                            "shared": False,
                            "adminStateUp": True,
                            "tenant_id": "test-tenant",
                            "segmentationId": None,
                            "physicalNetwork": None,
                            "networkType": "local",
                            "name": "net1"}}
        resp = self._mock_req_resp(requests.codes.no_content)
        kwargs = {'url': url, 'data': data}
        with mock.patch('requests.request',
                        return_value=resp) as mock_method:
            mock_method.side_effect = requests.exceptions.\
                Timeout(mock.Mock(msg="Timeout Exceptions"))
            ac_rest.RestClient().\
                process_request(methodname, auth, url, headers, data)
            mock_method.\
                assert_any_call(methodname,
                                headers={'Content-type':
                                         'application/json',
                                         'Accept':
                                         'application/json'},
                                timeout=float(cfg.CONF.
                                              huawei_ac_config.
                                              request_timeout),
                                verify=False,
                                auth=(cfg.CONF.huawei_ac_config.username,
                                      cfg.CONF.huawei_ac_config.password),
                                **kwargs)

    def test_rc_process_request_exception(self):
        methodname = 'DELETE'
        url = '/controller/dc/esdk/v2.0/test_url'
        auth = (cfg.CONF.huawei_ac_config.username,
                cfg.CONF.huawei_ac_config.password)
        headers = {'Accept': 'application/json',
                   'Content-type': 'application/json'}
        data = {"network": {"routerExternal": False,
                            "id": "d897e21a-dfd6-4331-a5dd-7524fa421c3e",
                            "serviceName": "physnet1",
                            "status": "ACTIVE",
                            "shared": False,
                            "adminStateUp": True,
                            "tenant_id": "test-tenant",
                            "segmentationId": None,
                            "physicalNetwork": None,
                            "networkType": "local",
                            "name": "net1"}}
        resp = self._mock_req_resp(requests.codes.no_content)
        kwargs = {'url': url, 'data': data}
        with mock.patch('requests.request',
                        return_value=resp) as mock_method:
            mock_method.side_effect = Exception(mock.Mock(msg="Timeout "
                                                              "Exceptions"))
            ac_rest.RestClient().process_request(methodname, auth,
                                                 url,
                                                 headers, data)
            mock_method.\
                assert_any_call(methodname,
                                headers={'Content-type':
                                         'application/json',
                                         'Accept':
                                         'application/json'},
                                timeout=float(cfg.CONF.
                                              huawei_ac_config.
                                              request_timeout),
                                verify=False,
                                auth=(cfg.CONF.huawei_ac_config.username,
                                      cfg.CONF.huawei_ac_config.password),
                                **kwargs)

    def test_rc_send_http_success(self):
        http = {'errorCode': None, 'reason': None,
                'response': None, 'status': 300}
        ret = ac_rest.RestClient().http_success(http)
        self.assertEqual(False, ret,
                         "Not expected response")
