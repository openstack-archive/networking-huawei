# Copyright (C) 2016 Huawei Technologies India Pvt Ltd.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
#

import copy
import mock
import requests
from webob import exc

from oslo_config import cfg
from oslo_serialization import jsonutils

from neutron.db.l3_db import L3_NAT_db_mixin
from neutron.db.l3_dvr_db import L3_NAT_with_dvr_db_mixin
from neutron.db.l3_hamode_db import L3_HA_NAT_db_mixin
from neutron.extensions import l3
from neutron.plugins.common import constants
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import base as test_neutron_extensions

from networking_huawei.common import constants as ac_const
from networking_huawei.common import exceptions as ml2_exc
import networking_huawei.drivers.ac.client.restclient as ac_rest
from networking_huawei.drivers.ac.plugins.l3.driver import \
    HuaweiACL3RouterPlugin

fake_tenant_id = '048aa98a3ec345dc8b14427c81e276cf'

fake_router_uuid = '292f7967-c5e7-47d8-8265-dc2160678b75'
fake_router_object = {'router': {'name': 'router_abc',
                                 'external_gateway_info': None,
                                 'admin_state_up': True,
                                 'tenant_id': fake_tenant_id}}

fake_network_id = '7464aaf0-27ea-448a-97df-51732f9e0e27'
fake_router_external_info = {'external_gateway_info':
                             {'network_id': fake_network_id,
                              'enable_snat': False}}

fake_floating_ip_id = '7464aaf0-27ea-448a-97df-51732f9e0e25'
fake_floating_ip = {'floatingip':
                    {'fixed_ip_address': '10.1.1.1',
                     'id': fake_floating_ip_id,
                     'router_id': fake_router_uuid,
                     'port_id': None,
                     'status': None,
                     'tenant_id': fake_tenant_id}}

fake_port_id = '7db560e9-76d4-4bf9-9c28-43efa7afa45d'
fake_subnet_id = 'dc2b8071-c24c-4a8e-b471-dbf3fbe55830'
fake_port = {'id': fake_port_id,
             'network_id': fake_network_id,
             'fixed_ips': [{'ip_address': '21.41.4.5',
                            'prefixlen': 28,
                            'subnet_id': fake_subnet_id}],
             'subnets': [{'id': fake_subnet_id,
                          'cidr': '21.41.4.0/28',
                          'gateway_ip': '21.41.4.1'}]}

fake_floating_ip_update_info = {'floating_network_id': fake_network_id,
                                'tenant_id': fake_tenant_id,
                                'fixed_ip_address': '20.1.1.11',
                                'subnet_id': fake_port['subnets'][0]['id'],
                                'port_id': fake_port_id,
                                'floating_ip_address': '198.1.2.3'}

fake_interface_add = {'subnet_id': fake_subnet_id}

fake_interface_remove = {'subnet_id': fake_subnet_id,
                         'port_id': fake_port_id}

fake_router_db = {'id': fake_router_uuid,
                  'name': 'router_abc',
                  'admin_state_up': True,
                  'tenant_id': fake_tenant_id,
                  'external_gateway_info': None,
                  'distributed': 'distributed',
                  'ha': True,
                  'routes': 'route1'}

fake_rest_headers = {"Content-type": "application/json",
                     "Accept": "application/json"}


class HuaweiACL3RouterPluginTest(test_neutron_extensions.ExtensionTestCase):
    def setUp(self):
        cfg.CONF.set_override('username', 'huawei_user', 'huawei_ac_config')
        cfg.CONF.set_override('password', 'huawei_pwd', 'huawei_ac_config')
        cfg.CONF.set_override('neutron_ip', '127.0.0.1', 'huawei_ac_config')
        cfg.CONF.set_override('neutron_name', 'NS_1', 'huawei_ac_config')
        super(HuaweiACL3RouterPluginTest, self).setUp()
        self._setUpExtension(
            'neutron.extensions.l3.RouterPluginBase', None,
            l3.RESOURCE_ATTRIBUTE_MAP, l3.L3, None,
            allow_pagination=True, allow_sorting=True,
            supported_extension_aliases=['router'],
            use_quota=True)
        self.instance = self.plugin.return_value
        self.restc = ac_rest.RestClient

    def _test_send_msg(self, dict_info, oper_type, url):
        if oper_type == 'post':
            resp = self.api.post(url, self.serialize(dict_info))
        elif oper_type == 'put':
            resp = self.api.put(url, self.serialize(dict_info))
        else:
            resp = self.api.delete(url)
        return resp

    def _create_rest_response(self, statuscode=requests.codes.no_content,
                              resp='OK', errorcode='0', errormsg=None):
        response = mock.Mock(status_code=statuscode)
        response.response = resp
        response.errorcode = errorcode
        response.content = jsonutils.dumps({'result': resp,
                                            'errorCode': errorcode,
                                            'errorMsg': errormsg}, indent=2)
        return response

    def test_create_router(self):
        router_info = copy.deepcopy(fake_router_object['router'])
        router_info.update({'status': 'ACTIVE', 'id': fake_router_uuid})
        self.instance.create_router.return_value = router_info
        self.instance.get_routers_count.return_value = 0
        url = test_base._get_path('routers', fmt=self.fmt)
        resp = self._test_send_msg(fake_router_object, 'post', url)
        self.instance.create_router. \
            assert_called_once_with(mock.ANY, router=fake_router_object)
        self._verify_resp(resp, exc.HTTPCreated.code,
                          'router', fake_router_uuid)

    def test_create_router_success(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        router_in = {'id': fake_router_db['id'],
                     'name': fake_router_db['name'],
                     'adminStateUp': fake_router_db['admin_state_up'],
                     'tenant_id': fake_router_db['tenant_id'],
                     'externalGatewayInfo': fake_router_db[
                         'external_gateway_info'],
                     'distributed': fake_router_db['distributed'],
                     'ha': fake_router_db['ha'],
                     'routes': fake_router_db['routes']}

        body = {'router': router_in}

        response = self._create_rest_response(requests.codes.all_good)

        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value=response) as mock_method:
            with mock.patch.object(L3_NAT_db_mixin, 'create_router',
                                   return_value=fake_router_db):
                acl3router = HuaweiACL3RouterPlugin()
                acl3router.create_router(context, router_info)

        tst_url = "http://" + cfg.CONF.huawei_ac_config.host + ":" \
                  + str(cfg.CONF.huawei_ac_config.port) + ac_const.NW_HW_URL \
                  + '/' \
                  + ac_const.NW_HW_NEUTRON_RESOURCES['create_router']['rsrc']
        params = jsonutils.dumps(body)
        mock_method.\
            assert_called_once_with(ac_const.NW_HW_NEUTRON_RESOURCES
                                    ['create_router']['method'],
                                    (cfg.CONF.huawei_ac_config.username,
                                     cfg.CONF.huawei_ac_config.password),
                                    tst_url, fake_rest_headers, params)

    def test_create_router_no_content(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        router_in = {'id': fake_router_db['id'],
                     'name': fake_router_db['name'],
                     'adminStateUp': fake_router_db['admin_state_up'],
                     'tenant_id': fake_router_db['tenant_id'],
                     'externalGatewayInfo': fake_router_db
                     ['external_gateway_info'],
                     'distributed': fake_router_db['distributed'],
                     'ha': fake_router_db['ha'],
                     'routes': fake_router_db['routes']}

        body = {'router': router_in}

        response = self._create_rest_response(requests.codes.no_content)

        with mock.patch.object(ac_rest.RestClient,
                               'process_request',
                               return_value=response) as mock_method:
            with mock.patch.object(L3_NAT_db_mixin,
                                   'create_router',
                                   return_value=fake_router_db):
                acl3router = HuaweiACL3RouterPlugin()
                acl3router.create_router(context, router_info)

        tst_url = "http://" + cfg.CONF.huawei_ac_config.host + ":" \
                  + str(cfg.CONF.huawei_ac_config.port) \
                  + ac_const.NW_HW_URL + '/' \
                  + ac_const.NW_HW_NEUTRON_RESOURCES[
                      'create_router']['rsrc']
        params = jsonutils.dumps(body)
        mock_method.\
            assert_called_once_with(ac_const.NW_HW_NEUTRON_RESOURCES
                                    ['create_router']['method'],
                                    (cfg.CONF.huawei_ac_config.username,
                                     cfg.CONF.huawei_ac_config.password),
                                    tst_url,
                                    fake_rest_headers, params)

    def test_create_router_failure(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        response = self._create_rest_response(requests.codes.bad_gateway)

        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value=response):
            with mock.patch.object(L3_NAT_db_mixin,
                                   'create_router',
                                   return_value=fake_router_db):
                acl3router = HuaweiACL3RouterPlugin()
                self.assertRaises(ml2_exc.MechanismDriverError,
                                  acl3router.create_router,
                                  context, router_info)

    def test_create_router_key_error_exception(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)
        del fake_router_db['tenant_id']
        with mock.patch.object(L3_NAT_db_mixin,
                               'create_router',
                               return_value=fake_router_db):
            acl3router = HuaweiACL3RouterPlugin()
            self.assertRaises(KeyError,
                              acl3router.create_router,
                              context, router_info)
        fake_router_db.update({'tenant_id': fake_tenant_id})

    def test_create_router_failure_with_errorcode(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        response = self._create_rest_response(requests.codes.ok, 'OK', '1')

        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value=response):
            with mock.patch.object(L3_NAT_db_mixin,
                                   'create_router',
                                   return_value=fake_router_db):
                acl3router = HuaweiACL3RouterPlugin()
                self.assertRaises(ml2_exc.MechanismDriverError,
                                  acl3router.create_router,
                                  context, router_info)

    def test_update_router(self):
        router_info = copy.deepcopy(fake_router_object['router'])
        router_info.update(fake_router_external_info)
        router_info.update({'status': 'ACTIVE', 'id': fake_router_uuid})
        self.instance.update_router.return_value = router_info
        router_request = {'router': fake_router_external_info}
        url = test_base._get_path('routers', id=fake_router_uuid, fmt=self.fmt)
        resp = self._test_send_msg(router_request, 'put', url)
        self.instance.update_router. \
            assert_called_once_with(mock.ANY, fake_router_uuid,
                                    router=router_request)
        self._verify_resp(resp, exc.HTTPOk.code, 'router', fake_router_uuid)

    def test_delete_router(self):
        url = test_base._get_path('routers', id=fake_router_uuid, fmt=self.fmt)
        resp = self._test_send_msg(None, 'delete', url)
        self.instance.delete_router.assert_called_once_with(mock.ANY,
                                                            fake_router_uuid)
        self.assertEqual(resp.status_int, exc.HTTPNoContent.code)

    def test_delete_router_success(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)
        response = self._create_rest_response(requests.codes.all_good)
        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value=response) as mock_method:
            with mock.patch.object(L3_HA_NAT_db_mixin, 'delete_router',
                                   return_value=fake_router_db):
                acl3router = HuaweiACL3RouterPlugin()
                acl3router.delete_router(context, fake_router_db['id'])

        tst_url = "http://" + cfg.CONF.huawei_ac_config.host + ":" \
                  + str(cfg.CONF.huawei_ac_config.port) + \
                  ac_const.NW_HW_URL + '/' + \
                  ac_const.NW_HW_NEUTRON_RESOURCES['delete_router']['rsrc'] \
                  + '/' + fake_router_db['id']
        params = jsonutils.dumps({})
        mock_method.\
            assert_called_once_with(ac_const.NW_HW_NEUTRON_RESOURCES
                                    ['delete_router']['method'],
                                    (cfg.CONF.huawei_ac_config.username,
                                     cfg.CONF.huawei_ac_config.password),
                                    tst_url,
                                    fake_rest_headers, params)

    def test_delete_router_direct_failure(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value="Timeout Exceptions") \
                as mock_method:
            with mock.patch.object(L3_HA_NAT_db_mixin, 'delete_router',
                                   return_value=fake_router_db):
                acl3router = HuaweiACL3RouterPlugin()
                acl3router.delete_router(context, fake_router_db['id'])

        tst_url = "http://" + cfg.CONF.huawei_ac_config.host + ":" \
                  + str(cfg.CONF.huawei_ac_config.port) \
                  + ac_const.NW_HW_URL + '/' + \
                  ac_const.NW_HW_NEUTRON_RESOURCES['delete_router']['rsrc'] \
                  + '/' + fake_router_db['id']
        params = jsonutils.dumps({})
        mock_method.\
            assert_called_once_with(ac_const.NW_HW_NEUTRON_RESOURCES
                                    ['delete_router']['method'],
                                    (cfg.CONF.huawei_ac_config.username,
                                     cfg.CONF.huawei_ac_config.password),
                                    tst_url, fake_rest_headers, params)

    def test_add_router_interface(self):
        interface_info = {'tenant_id': fake_tenant_id,
                          'port_id': fake_port_id,
                          'id': fake_router_uuid}
        interface_info.update(fake_interface_add)
        self.instance.add_router_interface.return_value = interface_info
        url = test_base._get_path('routers', id=fake_router_uuid,
                                  action='add_router_interface',
                                  fmt=self.fmt)
        resp = self._test_send_msg(fake_interface_add, 'put', url)
        self.instance.add_router_interface. \
            assert_called_once_with(mock.ANY, fake_router_uuid,
                                    fake_interface_add)
        self._verify_resp(resp, exc.HTTPOk.code, None, fake_router_uuid)

    def test_add_router_interface_success(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        interface_info = {'port_id': fake_port_id}

        router_in = {'portId': interface_info['port_id'],
                     'routerId': fake_router_db['id'],
                     'serviceName': cfg.CONF.huawei_ac_config.service_name,
                     'tenant_id': router_info['router']['tenant_id']}

        body = {'routerInterface': router_in}

        response = self._create_rest_response(requests.codes.all_good)

        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value=response) as mock_method:
            with mock.patch.object(L3_NAT_db_mixin, 'get_router',
                                   return_value=fake_router_db):
                with mock.patch.object(L3_NAT_with_dvr_db_mixin,
                                       'add_router_interface',
                                       return_value=interface_info):
                    acl3router = HuaweiACL3RouterPlugin()
                    acl3router.add_router_interface(context,
                                                    fake_router_db['id'],
                                                    interface_info)

        tst_url = "http://" + cfg.CONF.huawei_ac_config.host + ":" \
                  + str(cfg.CONF.huawei_ac_config.port) + ac_const.NW_HW_URL \
                  + '/' \
                  + ac_const.NW_HW_NEUTRON_RESOURCES[
                      'add_router_interface']['rsrc'] \
                  + '/' \
                  + fake_router_db['id']
        params = jsonutils.dumps(body)
        mock_method.\
            assert_called_once_with(ac_const.NW_HW_NEUTRON_RESOURCES
                                    ['add_router_interface']['method'],
                                    (cfg.CONF.huawei_ac_config.username,
                                     cfg.CONF.huawei_ac_config.password),
                                    tst_url, fake_rest_headers, params)

    def test_add_router_interface_key_error_exception(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        interface_info = {'port_id': fake_port_id}

        del interface_info['port_id']

        with mock.patch.object(L3_NAT_db_mixin, 'get_router',
                               return_value=fake_router_db):
            with mock.patch.object(L3_NAT_with_dvr_db_mixin,
                                   'add_router_interface',
                                   return_value=interface_info):
                acl3router = HuaweiACL3RouterPlugin()
                self.assertRaises(KeyError,
                                  acl3router.add_router_interface,
                                  context,
                                  fake_router_db['id'],
                                  interface_info)

    def test_remove_router_interface_key_error_exception(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        interface_info = {'port_id': fake_port_id}

        del interface_info['port_id']

        with mock.patch.object(L3_NAT_db_mixin, 'get_router',
                               return_value=fake_router_db):
            with mock.patch.object(L3_NAT_with_dvr_db_mixin,
                                   'remove_router_interface',
                                   return_value=interface_info):
                acl3router = HuaweiACL3RouterPlugin()
                self.assertRaises(KeyError,
                                  acl3router.remove_router_interface,
                                  context,
                                  fake_router_db['id'],
                                  interface_info)

    def test_remove_router_interface(self):
        interface_info = {'tenant_id': fake_tenant_id,
                          'id': fake_router_uuid}
        interface_info.update(fake_interface_remove)
        self.instance.remove_router_interface.return_value = interface_info
        url = test_base._get_path('routers', id=fake_router_uuid,
                                  action='remove_router_interface',
                                  fmt=self.fmt)
        resp = self._test_send_msg(fake_interface_remove, 'put', url)
        self.instance.remove_router_interface. \
            assert_called_once_with(mock.ANY, fake_router_uuid,
                                    fake_interface_remove)
        self._verify_resp(resp, exc.HTTPOk.code, None, fake_router_uuid)

    def test_remove_router_interface_success(self):
        router_info = copy.deepcopy(fake_router_object)
        router_info['router'].update({'status': 'ACTIVE',
                                      'id': fake_router_uuid})
        context = mock.Mock(current=fake_router_object)

        interface_info = {'port_id': fake_port_id}

        router_in = {'portId': interface_info['port_id'],
                     'id': fake_router_db['id'],
                     'serviceName': cfg.CONF.huawei_ac_config.service_name,
                     'tenant_id': router_info['router']['tenant_id']
                     }

        response = self._create_rest_response(requests.codes.all_good)

        with mock.patch.object(ac_rest.RestClient, 'process_request',
                               return_value=response) \
                as mock_method:
            with mock.patch.object(L3_NAT_db_mixin, 'get_router',
                                   return_value=fake_router_db):
                with mock.patch.object(L3_NAT_with_dvr_db_mixin,
                                       'remove_router_interface',
                                       return_value=interface_info):
                    acl3router = HuaweiACL3RouterPlugin()
                    acl3router.remove_router_interface(context,
                                                       fake_router_db['id'],
                                                       interface_info)

        tst_url = "http://" + cfg.CONF.huawei_ac_config.host + ":" \
                  + str(cfg.CONF.huawei_ac_config.port) \
                  + ac_const.NW_HW_URL + '/' \
                  + ac_const.NW_HW_NEUTRON_RESOURCES['delete_router'
                                                     '_interface']['rsrc'] \
                  + '/' + fake_router_db['id']
        params = jsonutils.dumps(router_in)
        mock_method.\
            assert_called_once_with(ac_const.NW_HW_NEUTRON_RESOURCES
                                    ['delete_router_interface']
                                    ['method'],
                                    (cfg.CONF.huawei_ac_config.username,
                                     cfg.CONF.huawei_ac_config.password),
                                    tst_url,
                                    fake_rest_headers,
                                    params)

    def _verify_resp(self, resp, return_code, context, id):
        self.assertEqual(resp.status_int, return_code)
        resp = self.deserialize(resp)

        if context is None:
            self.assertEqual(resp['id'], id)
            self.assertEqual(resp['subnet_id'], fake_subnet_id)
            return

        self.assertIn(context, resp)
        resource = resp[context]
        self.assertEqual(resource['id'], id)
        if context == 'router':
            self.assertEqual(resource['status'], 'ACTIVE')
            self.assertEqual(resource['admin_state_up'], True)

    def test_get_plugin_type(self):
        acl3router = HuaweiACL3RouterPlugin()
        plugin_type = acl3router.get_plugin_type()
        self.assertEqual(plugin_type, constants.L3_ROUTER_NAT)
        plugin_desc = acl3router.get_plugin_description()
        self.assertEqual(plugin_desc, ac_const.NW_HW_L3_DESCRIPTION)

    def test_rest_request_error_case(self):
        acl3router = HuaweiACL3RouterPlugin()
        self.assertRaises(ml2_exc.MechanismDriverError,
                          acl3router.__rest_request__,
                          None,
                          None,
                          'invalid_operation')
