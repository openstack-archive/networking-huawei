# coding:utf-8
# Copyright (c) 2016 OpenStack Foundation.
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

AC_NETWORKS = 'networks'
AC_SUBNETS = 'subnets'
AC_PORTS = 'ports'
AC_SNATS = 'snats'
AC_SEC_GRPS = 'neutronapi/security-groups'
AC_SEC_GRP_RULES = 'neutronapi/security-group-rules'
AC_ROUTERS = 'routers'
AC_ROUTER_IF = 'routerinterface'


AC_URL = "/controller/dc/esdk/v2.0"

AC_NEUTRON_RESOURCES = {'create_network': {'rsrc': AC_NETWORKS,
                                           'method': 'POST',
                                           'needSvcNameUpdate': True},
                        'delete_network': {'rsrc': AC_NETWORKS,
                                           'method': 'DELETE',
                                           'needSvcNameUpdate': False},
                        'update_network': {'rsrc': AC_NETWORKS,
                                           'method': 'PUT',
                                           'needSvcNameUpdate': False},
                        'create_subnet': {'rsrc': AC_SUBNETS,
                                          'method': 'POST',
                                          'needSvcNameUpdate': True},
                        'delete_subnet': {'rsrc': AC_SUBNETS,
                                          'method': 'DELETE',
                                          'needSvcNameUpdate': False},
                        'update_subnet': {'rsrc': AC_SUBNETS, 'method': 'PUT',
                                          'needSvcNameUpdate': False},
                        'create_port': {'rsrc': AC_PORTS, 'method': 'POST',
                                        'needSvcNameUpdate': True},
                        'delete_port': {'rsrc': AC_PORTS, 'method': 'DELETE',
                                        'needSvcNameUpdate': False},
                        'update_port': {'rsrc': AC_PORTS, 'method': 'PUT',
                                        'needSvcNameUpdate': False},
                        'delete_snat': {'rsrc': AC_SNATS, 'method': 'DELETE',
                                        'needSvcNameUpdate': False},
                        'create_security_group': {'rsrc': AC_SEC_GRPS,
                                                  'method': 'POST',
                                                  'needSvcNameUpdate': False},
                        'delete_security_group': {'rsrc': AC_SEC_GRPS,
                                                  'method': 'DELETE',
                                                  'needSvcNameUpdate': False},
                        'update_security_group': {'rsrc': AC_SEC_GRPS,
                                                  'method': 'PUT',
                                                  'needSvcNameUpdate': False},
                        'create_security_group_rule': {'rsrc':
                                                       AC_SEC_GRP_RULES,
                                                       'method': 'POST',
                                                       'needSvcNameUpdate':
                                                           False},
                        'delete_security_group_rule': {'rsrc':
                                                       AC_SEC_GRP_RULES,
                                                       'method': 'DELETE',
                                                       'needSvcNameUpdate':
                                                           False},
                        'create_router': {'rsrc': AC_ROUTERS, 'method': 'POST',
                                          'needSvcNameUpdate': False},
                        'delete_router': {'rsrc': AC_ROUTERS,
                                          'method': 'DELETE',
                                          'needSvcNameUpdate': False},
                        'add_router_interface': {
                            'rsrc': '%s%s' % (AC_ROUTER_IF,
                                              '/add_router_interface'),
                            'method': 'PUT', 'needSvcNameUpdate': False},
                        'delete_router_interface': {
                            'rsrc': '%s%s' % (AC_ROUTER_IF,
                                              '/remove_router_interface'),
                            'method': 'PUT', 'needSvcNameUpdate': False}}

AC_L3_DESCRIPTION = "Huawei L3 Router Service Plugin for basic L3 forwarding" \
                    " between (L2) Neutron networks and access to external" \
                    " networks via a NAT gateway."
