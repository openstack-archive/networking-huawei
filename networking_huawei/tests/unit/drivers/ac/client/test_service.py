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
from oslotest import base

import networking_huawei.drivers.ac.client.restclient as ac_rest
import networking_huawei.drivers.ac.client.service as ac_rest_service
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


class HuaweiACRestServiceTestCase(base.BaseTestCase):

    def setUp(self):
        super(HuaweiACRestServiceTestCase, self).setUp()
        self.rest_service = ac_rest_service.RESTService()
        self.ac_rest = ac_rest.RestClient
        self.host = cfg.CONF.huawei_ac_config.host
        self.port = cfg.CONF.huawei_ac_config.port
        self.url = '%s%s%s%s' % ("http://", self.host, ":", str(self.port))

    def test_service_requestREST(self):
        methodname = 'POST'
        url = '/controller/dc/esdk/v2.0/test_url'
        expected_resp = {'errorCode': u'0', 'reason': None,
                         'response': 'ok', 'status': 204}
        with mock.patch.object(self.ac_rest, 'send',
                               return_value=expected_resp):
            self.rest_service.requestREST(methodname, url, hex(10),
                                          test_create_network_req)

    def test_service_requestService(self):
        methodname = 'POST'
        url = '/controller/dc/esdk/v2.0/test_url'
        self.rest_service.requestService(methodname, url, hex(10),
                                         test_create_network_req)

    def test_service_requestService_servicename(self):
        methodname = 'POST'
        url = '/controller/dc/esdk/v2.0/test_url'
        self.rest_service.requestService(methodname, url, hex(10),
                                         test_create_network_req, True)

    def test_service_requestService_success(self):
        methodname = 'POST'
        url = '/controller/dc/esdk/v2.0/test_url'
        expected_resp = {'errorCode': u'0', 'reason': None, 'response': 'ok',
                         'status': requests.codes.ok}
        with mock.patch.object(self.rest_service, 'requestREST',
                               return_value=expected_resp):
            ret = self.rest_service.requestService(methodname, url, hex(10),
                                                   test_create_network_req,
                                                   True)
            self.assertEqual(None, ret, "Not expected return")
