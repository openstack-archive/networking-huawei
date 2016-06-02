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

NW_HW_AC_DRIVER_NAME = 'AC'
NW_HW_NETWORKS = 'networks'
NW_HW_SUBNETS = 'subnets'
NW_HW_PORTS = 'ports'
NW_HW_SNATS = 'snats'
NW_HW_SEC_GRPS = 'neutronapi/security-groups'
NW_HW_SEC_GRP_RULES = 'neutronapi/security-group-rules'
NW_HW_ROUTERS = 'routers'
NW_HW_ROUTER_IF = 'routerinterface'


NW_HW_URL = "/controller/dc/esdk/v2.0"

NW_HW_NEUTRON_RESOURCES = {'create_network': {'rsrc': NW_HW_NETWORKS,
                                              'method': 'POST',
                                              'needSvcNameUpdate': True},
                           'delete_network': {'rsrc': NW_HW_NETWORKS,
                                              'method': 'DELETE',
                                              'needSvcNameUpdate': False},
                           'update_network': {'rsrc': NW_HW_NETWORKS,
                                              'method': 'PUT',
                                              'needSvcNameUpdate': False},
                           'create_subnet': {'rsrc': NW_HW_SUBNETS,
                                             'method': 'POST',
                                             'needSvcNameUpdate': True},
                           'delete_subnet': {'rsrc': NW_HW_SUBNETS,
                                             'method': 'DELETE',
                                             'needSvcNameUpdate': False},
                           'update_subnet': {'rsrc': NW_HW_SUBNETS,
                                             'method': 'PUT',
                                             'needSvcNameUpdate': False},
                           'create_port': {'rsrc': NW_HW_PORTS,
                                           'method': 'POST',
                                           'needSvcNameUpdate': True},
                           'delete_port': {'rsrc': NW_HW_PORTS,
                                           'method': 'DELETE',
                                           'needSvcNameUpdate': False},
                           'update_port': {'rsrc': NW_HW_PORTS,
                                           'method': 'PUT',
                                           'needSvcNameUpdate': False},
                           'delete_snat': {'rsrc': NW_HW_SNATS,
                                           'method': 'DELETE',
                                           'needSvcNameUpdate': False},
                           'create_security_group': {'rsrc': NW_HW_SEC_GRPS,
                                                     'method': 'POST',
                                                     'needSvcNameUpdate':
                                                     False},
                           'delete_security_group': {'rsrc': NW_HW_SEC_GRPS,
                                                     'method': 'DELETE',
                                                     'needSvcNameUpdate':
                                                     False},
                           'update_security_group': {'rsrc': NW_HW_SEC_GRPS,
                                                     'method': 'PUT',
                                                     'needSvcNameUpdate':
                                                     False},
                           'create_security_group_rule': {'rsrc':
                                                          NW_HW_SEC_GRP_RULES,
                                                          'method': 'POST',
                                                          'needSvcNameUpdate':
                                                          False},
                           'delete_security_group_rule': {'rsrc':
                                                          NW_HW_SEC_GRP_RULES,
                                                          'method': 'DELETE',
                                                          'needSvcNameUpdate':
                                                          False},
                           'create_router': {'rsrc': NW_HW_ROUTERS,
                                             'method': 'POST',
                                             'needSvcNameUpdate': False},
                           'delete_router': {'rsrc': NW_HW_ROUTERS,
                                             'method': 'DELETE',
                                             'needSvcNameUpdate': False},
                           'add_router_interface': {
                               'rsrc': '%s%s' % (NW_HW_ROUTER_IF,
                                                 '/add_router_interface'),
                               'method': 'PUT', 'needSvcNameUpdate': False},
                           'delete_router_interface': {
                               'rsrc': '%s%s' % (NW_HW_ROUTER_IF,
                                                 '/remove_router_interface'),
                               'method': 'PUT', 'needSvcNameUpdate': False}}

NW_HW_L3_DESCRIPTION = "Huawei L3 Router Service Plugin for basic L3 " \
                       "forwarding between (L2) Neutron networks and " \
                       "access to external networks via a NAT gateway."
