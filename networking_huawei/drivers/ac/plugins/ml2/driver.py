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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron import context
from neutron.db import common_db_mixin
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import portbindings
from neutron.plugins.common import constants as n_const
from neutron.plugins.ml2 import driver_api as api
from neutron_lib import constants as q_const

from networking_huawei._i18n import _LE
from networking_huawei._i18n import _LI
from networking_huawei._i18n import _LW
from networking_huawei.common import constants as ac_const
from networking_huawei.common import exceptions as ml2_exc
from networking_huawei.drivers.ac.client.service import RESTService
from networking_huawei.drivers.ac.common import config  # noqa


LOG = logging.getLogger(__name__)


@log_helpers.log_method_call
def create_security_group(resource, event, trigger, **kwargs):
    """Subscribed for security group creation

    :param resource: Security group resources
    :param event: Event
    :param trigger: Trigger for the call
    :param kwargs: Args
    :return: None
    """

    security_group = kwargs['security_group']
    ctx = context.get_admin_context()
    try:
        securitygroupdb = SecurityGroupDbManager()
        sg_group = securitygroupdb \
            .get_security_group(ctx, security_group['id'])
        security_group['security_group_rules'] = \
            sg_group['security_group_rules']
    except Exception:
        LOG.warning(_LW("The SG group does not exist."))

    security_group_info = _set_security_group(security_group)
    LOG.debug("The security group_info is %s.",
              security_group_info)
    try:
        rest_request(security_group_info['id'],
                     {'securityGroup': security_group_info},
                     'create_security_group')
    except Exception:
        create_security_group_rollback(security_group_info['id'])
    LOG.debug("Finish creating security group.")


@log_helpers.log_method_call
def create_security_group_rollback(group_id):
    """Rollback the security group subscription

    :param group_id: Group id of the security group
    :return: None
    """

    try:
        rest_request(group_id, {}, 'delete_security_group')
    except Exception:
        LOG.error(_LE("Rollback for create security group failed."))


@log_helpers.log_method_call
def update_security_group(resource, event, trigger, **kwargs):
    """Subscribed for security group update

    :param resource: Security group resources
    :param event: Event
    :param trigger: Trigger for the call
    :param kwargs: Args
    :return: None
    """

    security_group = kwargs['security_group']
    security_group_info = _set_security_group(security_group)
    LOG.debug("The group is %s.", security_group_info)
    try:
        rest_request(security_group_info['id'],
                     {'securityGroup': security_group_info},
                     'update_security_group')
    except Exception:
        LOG.error(_LE("Update security group failed."))

    LOG.debug("End update security group.")


@log_helpers.log_method_call
def delete_security_group(resource, event, trigger, **kwargs):
    """Subscribed for security group delete

    :param resource: Security group resources
    :param event: Event
    :param trigger: Trigger for the call
    :param kwargs: Args
    :return: None
    """

    group_id = kwargs['security_group_id']
    LOG.debug("The group id is %s.", group_id)
    try:
        rest_request(group_id, {}, 'delete_security_group')
    except Exception:
        LOG.error(_LE("Delete security group fail."))

    LOG.debug("End delete security group.")


@log_helpers.log_method_call
def create_security_group_rule(resource, event, trigger, **kwargs):
    """Subscribed for security group rule creation

    :param resource: Security group resources
    :param event: Event
    :param trigger: Trigger for the call
    :param kwargs: Args
    :return: None
    """

    rule = kwargs['security_group_rule']
    rule_info = _set_security_group_rule(rule)
    LOG.debug("The group rule is %s.", rule_info)
    try:
        rest_request(
            rule_info['id'],
            {'securityGroupRule': rule_info},
            'create_security_group_rule')
    except Exception:
        LOG.error(_LE("Create \
            security group rule failed, rollback.")),
        create_security_group_rule_rollback(rule_info['id'])

    LOG.debug("End create security group rule.")


@log_helpers.log_method_call
def create_security_group_rule_rollback(rule_id):
    """Rollback the security group rule subscription

    :param group_id: Group id of the security group
    :return: None
    """

    try:
        rest_request(rule_id, {}, 'delete_security_group_rule')
    except Exception:
        LOG.error(_LE("Rollback group rule failed."))


@log_helpers.log_method_call
def delete_security_group_rule(resource, event, trigger, **kwargs):
    """Subscribed for security group rule delete

    :param resource: Security group resources
    :param event: Event
    :param trigger: Trigger for the call
    :param kwargs: Args
    :return: None
    """

    rule_id = kwargs['security_group_rule_id']
    try:
        rest_request(rule_id, {}, 'delete_security_group_rule')
    except Exception:
        LOG.error(_LE("Delete security group rule failed."))
    LOG.debug("End delete security group rule.")


@log_helpers.log_method_call
def delete_snat(resource, event, trigger, **kwargs):
    """Subscribed for source NAT deletion

    :param resource: Security group resources
    :param event: Event
    :param trigger: Trigger for the call
    :param kwargs: Args
    :return: None
    """

    router_id = kwargs['router_id']
    try:
        rest_request(router_id, {}, 'delete_snat')
    except Exception:
        LOG.error(_LE("Delete SNAT failed."))
    LOG.debug("End delete SNAT.")


def _set_security_group(security_group):
    security_group_info = {}
    security_group_info['tenant_id'] = security_group['tenant_id']
    security_group_info['name'] = security_group['name']
    security_group_info['description'] = security_group['description']
    security_group_info['id'] = security_group['id']
    rule_arr = []
    for security_group_rule in security_group['security_group_rules']:
        rule_info = {'tenant_id': security_group_rule['tenant_id'],
                     'remoteGroupId': security_group_rule['remote_group_id'],
                     'direction': security_group_rule['direction'],
                     'remoteIpPrefix': security_group_rule['remote_ip_prefix'],
                     'protocol': security_group_rule['protocol'],
                     'portRangeMax': security_group_rule['port_range_max'],
                     'portRangeMin': security_group_rule['port_range_min'],
                     'id': security_group_rule['id'],
                     'etherType': security_group_rule['ethertype'],
                     'securityGroupId': security_group_rule[
                         'security_group_id']}
        rule_arr.append(rule_info)

    security_group_info['securityGroupRuleList'] = rule_arr
    return security_group_info


def _set_security_group_rule(rule):
    rule_info = {'remoteGroupId': rule['remote_group_id'],
                 'direction': rule['direction'],
                 'remoteIpPrefix': rule['remote_ip_prefix'],
                 'protocol': rule['protocol'],
                 'etherType': rule['ethertype'],
                 'tenant_id': rule['tenant_id'],
                 'portRangeMax': rule['port_range_max'],
                 'portRangeMin': rule['port_range_min'],
                 'id': rule['id'],
                 'securityGroupId': rule['security_group_id']}
    return rule_info


@log_helpers.log_method_call
def rest_request(id, entry_info, operation):

    if operation in ac_const.NW_HW_NEUTRON_RESOURCES:
        methodname = ac_const.NW_HW_NEUTRON_RESOURCES[operation]['method']
        url = '%s%s%s' % (ac_const.NW_HW_URL, '/',
                          ac_const.NW_HW_NEUTRON_RESOURCES[operation]['rsrc'])
        service = RESTService()

        LOG.debug("The ac data is: %s.", jsonutils.dumps(entry_info))
        try:
            if operation == 'create_security_group' \
                    and entry_info['securityGroup']['name'] == 'default':
                service.requestService(methodname,
                                       url,
                                       id,
                                       entry_info,
                                       False,
                                       default_security_group_rest_callback)
            else:
                service.requestService(methodname,
                                       url,
                                       id,
                                       entry_info,
                                       False,
                                       rest_callback)
        except Exception as e:
            LOG.error(_LE("Exception is %s."), e)
    else:
        LOG.debug("The operation is wrong.")
        raise ml2_exc.MechanismDriverError(method='rest_request')


@log_helpers.log_method_call
def rest_callback(errorcode, reason, status, data=None):
    if status == req_code.ok and reason is None:
        if errorcode != '0':
            LOG.error(_LE("Raise MechanismDriverError."))
            raise ml2_exc.MechanismDriverError(method='rest_callback')
    elif status == req_code.no_content:
        pass
    else:
        LOG.error(_LE("Raise MechanismDriverError."))


@log_helpers.log_method_call
def default_security_group_rest_callback(
        errorcode, reason, status, data=None):
    if status == req_code.ok and reason is None:
        if errorcode != '0':
            LOG.error(_LE("Raise MechanismDriverError."))
            raise ml2_exc.MechanismDriverError(method="default_security_"
                                                      "group_rest_callback")
    elif status == req_code.no_content:
        pass
    else:
        LOG.error(_LE("Default security group processing error."))


class SecurityGroupDbManager(
        sg_db.SecurityGroupDbMixin, common_db_mixin.CommonDbMixin):
    pass


class HuaweiACMechanismDriver(api.MechanismDriver):
    def initialize(self):
        LOG.info(_LI("Init huawei ml2 driver."))
        self.ctx = context.get_admin_context()
        self.securityGroupDb = SecurityGroupDbManager()
        registry.subscribe(
            delete_snat, resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
        registry.subscribe(
            create_security_group, resources.SECURITY_GROUP,
            events.AFTER_CREATE)
        registry.subscribe(
            update_security_group, resources.SECURITY_GROUP,
            events.AFTER_UPDATE)
        registry.subscribe(
            delete_security_group, resources.SECURITY_GROUP,
            events.AFTER_DELETE)
        registry.subscribe(
            create_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_CREATE)
        registry.subscribe(
            delete_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_DELETE)
        LOG.info(_LI("Initialization finished successfully for "
                     "huawei ml2 driver."))

    @log_helpers.log_method_call
    def create_network_postcommit(self, context):
        """This function sends network create message to AC

        :param context: DB context for the network creation
        :return: None
        """
        network_info = self.__setNetWorkInfo__(context)
        self.__restRequest__("", network_info, 'create_network')

    @log_helpers.log_method_call
    def delete_network_postcommit(self, context):
        """This function sends network delete message to AC

        :param context: DB context for the network delete
        :return: None
        """
        network_info = self.__setNetWorkInfo__(context)
        self.__restRequest__(network_info['network']['id'], {},
                             'delete_network')

    @log_helpers.log_method_call
    def update_network_postcommit(self, context):
        """This function sends network update message to AC

        :param context: DB context for the network update
        :return: None
        """
        network_info = self.__setNetWorkInfo__(context)
        self.__restRequest__(network_info['network']['id'], network_info,
                             'update_network')

    def __setNetWorkInfo__(self, context):
        LOG.debug("The context current in network is %s.", context.current)
        try:
            network_info = {'id': context.current['id'],
                            'status': context.current['status'],
                            'segmentationId': context.current['provider:'
                                                              'segmentation'
                                                              '_id'],
                            'tenant_id': context.current['tenant_id'],
                            'name': context.current['name'],
                            'adminStateUp': context.current['admin_state_up'],
                            'shared': context.current['shared'],
                            'networkType': context.current['provider:'
                                                           'network_type'],
                            'physicalNetwork': context.current['provider:'
                                                               'physical_'
                                                               'network']}
        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        if 'router:external' in context.current \
                and context.current['router:external']:
            network_info['routerExternal'] = True
            LOG.debug("The request if for an external network.")
        else:
            network_info['routerExternal'] = False
            LOG.debug("The request if for an internal network.")
        LOG.debug("The network_info is %s.", network_info)
        network_info1 = {'network': network_info}
        return network_info1

    @log_helpers.log_method_call
    def create_subnet_postcommit(self, context):
        """This function sends subnet create message to AC

        :param context: DB context for the subnet creation
        :return: None
        """
        subnet_info = self.__setSubNetinfo__(context)
        self.__restRequest__("", subnet_info, 'create_subnet')

    @log_helpers.log_method_call
    def delete_subnet_postcommit(self, context):
        """This function sends subnet delete message to AC

        :param context: DB context for the subnet delete
        :return: None
        """
        subnet_info = self.__setSubNetinfo__(context)
        self.__restRequest__(subnet_info['subnet']['id'], {}, 'delete_subnet')

    @log_helpers.log_method_call
    def update_subnet_postcommit(self, context):
        """This function sends subnet update message to AC

        :param context: DB context for the subnet update
        :return: None
        """
        subnet_info = self.__setSubNetinfo__(context)
        self.__restRequest__(
            subnet_info['subnet']['id'], subnet_info, 'update_subnet')

    def __setSubNetinfo__(self, context):
        LOG.debug("The context current in subnet is %s.", context.current)
        try:
            subnet_info = {'networkId': context.current['network_id'],
                           'tenant_id': context.current['tenant_id'],
                           'id': context.current['id'],
                           'name': context.current['name'],
                           'ipVersion': context.current['ip_version'],
                           'enableDhcp': context.current['enable_dhcp'],
                           'allocationPools': context.current
                           ['allocation_pools'],
                           'cidr': context.current['cidr'],
                           'gatewayIp': context.current['gateway_ip'],
                           'dnsNameservers': context.current
                           ['dns_nameservers'],
                           'hostRoutes': context.current['host_routes']}

            subnet_info_list = {}
            if q_const.IP_VERSION_6 == context.current['ip_version']:
                subnet_info['ipv6AddressMode'] \
                    = context.current['ipv6_address_mode']
                subnet_info['ipv6RaMode'] = context.current['ipv6_ra_mode']

        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        LOG.debug("The subnet_info is %s.", subnet_info)
        subnet_info_list['subnet'] = subnet_info
        return subnet_info_list

    @log_helpers.log_method_call
    def create_port_postcommit(self, context):
        """This function sends port create message to AC

        :param context: DB context for the port creation
        :return: None
        """
        self.__deal_port__(context, 'create_port')

    @log_helpers.log_method_call
    def update_port_postcommit(self, context):
        """This function sends port update message to AC

        :param context: DB context for the port update
        :return: None
        """
        self.__deal_port__(context, 'update_port')

    @log_helpers.log_method_call
    def delete_port_postcommit(self, context):
        """This function sends port delete message to AC

        :param context: DB context for the port delete
        :return: None
        """

        try:
            port_info = self.__setPortinfo__(context)
        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        self.__restRequest__(port_info['port']['id'], port_info, 'delete_port')

    def __deal_port__(self, context, operation):
        LOG.debug("The context current in port is %s.", context.current)
        try:
            port_info = self.__setPortinfo__(context)
        except KeyError as e:
            LOG.error(_LE("Key Error, doesn't contain all fields %s."), e)
            raise KeyError

        # if the port bind default security group and not sync to ac,
        # it need to be sync to ac
        if operation == 'create_port':
            for security_group_id in context.current['security_groups']:
                sg_group = self \
                    .securityGroupDb.get_security_group(
                        self.ctx, security_group_id)
                security_group_info = _set_security_group(sg_group)
                if security_group_info['name'] == 'default':
                    LOG.info(_LI("security_group_info is %s"),
                             security_group_info)
                    rest_request(security_group_info['id'],
                                 {'securityGroup': security_group_info},
                                 'create_security_group')
        LOG.debug("The port_info is %s.", port_info)
        self.__restRequest__(port_info['port']['id'], port_info, operation)

    @log_helpers.log_method_call
    def bind_port(self, context):
        """This function sends bind port to VM message to AC

        :param context: DB context for the port binding
        :return: None
        """
        for segment in context.segments_to_bind:
            if self.check_segment(segment):
                context._new_bound_segment = segment[api.ID]
                vif_details = {portbindings.OVS_HYBRID_PLUG: True}
                context.set_binding(segment[api.ID],
                                    'ovs',
                                    vif_details)
            else:
                LOG.debug("Port bound un-successfull for segment ID %(id)s, "
                          "segment %(seg)s, phys net %(physnet)s, and "
                          "network type %(nettype)s",
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    @log_helpers.log_method_call
    def check_segment(self, segment):
        """Check whether segment is valid for the AC MechanismDriver."""

        return segment[api.NETWORK_TYPE] in [n_const.TYPE_LOCAL,
                                             n_const.TYPE_GRE,
                                             n_const.TYPE_VXLAN,
                                             n_const.TYPE_VLAN]

    def __setPortinfo__(self, context):
        LOG.debug("The context current in Port is %s.", context.current)
        port_info = {'id': context.current['id'],
                     'name': context.current['name'],
                     'networkId': context.current['network_id'],
                     'tenantId': context.current['tenant_id'],
                     'hostId': context.current['binding:host_id'],
                     'macAddress': context.current['mac_address'],
                     'adminStateUp': context.current['admin_state_up'],
                     'deviceOwner': context.current['device_owner'],
                     'profile': {}}

        port_info['profile']['localLinkInformations'] = []
        port_info1 = {}
        if 'binding:profile' in context.current \
                and 'local_link_information' \
                in context.current['binding:profile']:
            for link in context \
                    .current['binding:profile']['local_link_information']:
                link_ac = {'switchId': link['swich_id'],
                           'mgmtIp': link['mgmtIP'],
                           'bondType': link['bondtype'],
                           'portId': link['port_id'],
                           'switchInfo': link['switch_info']}
                port_info['profile']['localLinkInformations'].append(link_ac)
                port_info['vifType'] = context.current['binding:vif_type']
                port_info['vnicType'] = context.current['binding:vnic_type']
                port_info['deviceId'] = context.current['device_id']
                port_info['status'] = context.current['status']
        if context.current['fixed_ips']:
            fixedIps = {}
            fixedIp = []
            for item in context.current['fixed_ips']:
                fixedIps['subnetId'] = item['subnet_id']
                fixedIps['ipAddress'] = item['ip_address']
                fixedIp.append(fixedIps)
            port_info['fixedIps'] = fixedIp
        port_info['sercurityGroups'] = context.current['security_groups']
        LOG.debug("The port_info is %s.", port_info)
        port_info1['port'] = port_info
        return port_info1

    @log_helpers.log_method_call
    def __restRequest__(self, id, entry_info, operation):
        if operation in ac_const.NW_HW_NEUTRON_RESOURCES:
            isneedservicename = \
                ac_const.NW_HW_NEUTRON_RESOURCES[operation][
                    'needSvcNameUpdate']
            methodname = ac_const.NW_HW_NEUTRON_RESOURCES[operation]['method']
            url = '%s%s%s' % (ac_const.NW_HW_URL, '/',
                              ac_const.NW_HW_NEUTRON_RESOURCES[operation][
                                  'rsrc'])

            service = RESTService()
            service.requestService(methodname,
                                   url,
                                   id,
                                   entry_info,
                                   isneedservicename,
                                   self.__callBack__)
        else:
            LOG.error(_LE("The operation is wrong."))
            raise ml2_exc.MechanismDriverError(method='__restRequest__')

    @log_helpers.log_method_call
    def __callBack__(self, errorCode, reason, status):
        if status == req_code.ok and reason is None:
            if errorCode != '0':
                LOG.debug("Error code not ok, report mechanism driver error.")
                raise ml2_exc.MechanismDriverError(method='__callBack__')
        elif status == req_code.no_content:
            pass
        else:
            LOG.debug("Status not ok, report mechanism driver error.")
            raise ml2_exc.MechanismDriverError(method='__callBack__')
