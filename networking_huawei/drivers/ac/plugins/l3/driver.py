# Copyright 2016 Huawei Technologies Co. Ltd. All rights reserved.
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

from requests import codes as req_code

from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.plugins.common import constants
from neutron.services.l3_router import l3_router_plugin
from neutron_lib import constants as q_const

from networking_huawei._i18n import _LE
from networking_huawei._i18n import _LI
from networking_huawei.common import constants as ac_const
from networking_huawei.common import exceptions as ml2_exc
from networking_huawei.drivers.ac.client.service import RESTService
from networking_huawei.drivers.ac.common import config  # noqa


LOG = logging.getLogger(__name__)


class HuaweiACL3RouterPlugin(l3_router_plugin.L3RouterPlugin):

    """Implementation of the Neutron L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB related work is implemented in classes
    l3_db.L3_NAT_db_mixin, l3_hamode_db.L3_HA_NAT_db_mixin,
    l3_dvr_db.L3_NAT_with_dvr_db_mixin, and extraroute_db.ExtraRoute_db_mixin.
    """

    def __init__(self):
        LOG.info(_LI("Init huawei l3 driver."))
        self.setup_rpc()
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.start_periodic_l3_agent_status_check()
        super(HuaweiACL3RouterPlugin, self).__init__()
        if 'dvr' in self.supported_extension_aliases:
            l3_dvrscheduler_db.subscribe()
        l3_db.subscribe()
        LOG.info(_LI("Initialization finished successfully"
                 " for huawei l3 driver."))

    def setup_rpc(self):
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection()
        self.agent_notifiers.update(
            {q_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [l3_rpc.L3RpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    @log_helpers.log_method_call
    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    @log_helpers.log_method_call
    def get_plugin_description(self):
        """returns string description of the plugin."""
        return (ac_const.NW_HW_L3_DESCRIPTION)

    @log_helpers.log_method_call
    def create_router(self, context, router):
        router_db = super(HuaweiACL3RouterPlugin, self)\
            .create_router(context, router)
        LOG.debug('Create router db %s.', router_db)

        try:
            routerinfo = {'id': router_db['id'],
                          'name': router_db['name'],
                          'adminStateUp': router_db['admin_state_up'],
                          'tenant_id': router_db['tenant_id'],
                          'externalGatewayInfo': router_db['external_'
                                                           'gateway_info'],
                          'distributed': router_db['distributed'],
                          'ha': router_db['ha'],
                          'routes': router_db['routes']}
        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        info = {'router': routerinfo}
        self.__rest_request__("", info, 'create_router')
        return router_db

    @log_helpers.log_method_call
    def add_router_interface(self, context, router_id, interface_info):
        interface_info = super(HuaweiACL3RouterPlugin, self)\
            .add_router_interface(context, router_id, interface_info)

        router = super(HuaweiACL3RouterPlugin, self)\
            .get_router(context, router_id)

        LOG.debug('Interface info of add_router_interface %s.', interface_info)
        LOG.debug('Router data of add_router_interface %s.', router)

        service = RESTService()

        service_name = service.serviceName
        rest_info = {}
        try:
            info = {'portId': interface_info['port_id'],
                    'routerId': router_id,
                    'serviceName': service_name,
                    'tenant_id': router['tenant_id']}
        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        rest_info['routerInterface'] = info

        self.__rest_request__(router_id, rest_info, 'add_router_interface')

    @log_helpers.log_method_call
    def remove_router_interface(self, context, router_id, interface_info):
        router = super(HuaweiACL3RouterPlugin, self)\
            .get_router(context, router_id)

        interface_info = super(HuaweiACL3RouterPlugin, self)\
            .remove_router_interface(context, router_id, interface_info)

        LOG.debug('Interface info of remove_router_interface %s.',
                  interface_info)
        LOG.debug('Router data of remove_router_interface %s.', router)

        service = RESTService()
        service_name = service.serviceName

        try:
            rest_info = {'portId': interface_info['port_id'],
                         'id': router_id,
                         'serviceName': service_name,
                         'tenant_id': router['tenant_id']}
        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        self.__rest_request__(router_id, rest_info, 'delete_router_interface')

    @log_helpers.log_method_call
    def delete_router(self, context, res_id):
        self.__rest_request__(res_id, {}, 'delete_router')
        super(HuaweiACL3RouterPlugin, self).delete_router(context, res_id)

    @log_helpers.log_method_call
    def __rest_request__(self, res_id, entry_info, operation):
        if operation in ac_const.NW_HW_NEUTRON_RESOURCES:
            methodname = ac_const.NW_HW_NEUTRON_RESOURCES[operation]['method']
            url = '%s%s%s' % (ac_const.NW_HW_URL, '/',
                              ac_const.NW_HW_NEUTRON_RESOURCES
                              [operation]['rsrc'])
            service = RESTService()
            service.requestService(methodname, url, res_id,
                                   entry_info, False, self.__callBack__)
        else:
            LOG.debug("The operation is wrong.")
            raise ml2_exc.MechanismDriverError(
                driver=ac_const.NW_HW_AC_DRIVER_NAME,
                method='__rest_request__')

    @log_helpers.log_method_call
    def __callBack__(self, errorcode, reason, status):
        if status == req_code.ok and reason is None:
            if errorcode != '0':
                LOG.debug("Error code not ok, report mechanism driver error.")
                raise ml2_exc.MechanismDriverError(
                    driver=ac_const.NW_HW_AC_DRIVER_NAME,
                    method='__callBack__')
        elif status == req_code.no_content:
            pass
        else:
            LOG.debug("Status not ok, report mechanism driver error.")
            raise ml2_exc.MechanismDriverError(
                driver=ac_const.NW_HW_AC_DRIVER_NAME,
                method='__callBack__')
