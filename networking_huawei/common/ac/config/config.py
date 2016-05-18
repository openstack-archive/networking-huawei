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

# Function: Setting configuration parameters in a global variables


from oslo_config import cfg

from networking_huawei._i18n import _

HUAWEI_AC_DRIVER_OPTS = [
    cfg.StrOpt('host',
               default='',
               help=_('AC ReST interface IP.')),
    cfg.IntOpt('port',
               default=32102,
               help=_("AC ReST interface port number.")),
    cfg.StrOpt('username',
               default='',
               help=_('Username for authentication.')),
    cfg.StrOpt('password',
               default='',
               secret=True,  # do not expose value in the logs
               help=_('Password for authentication.')),
    cfg.StrOpt('neutron_name',
               default='NeutronServer1',
               help=_('Neutron server name.')),
    cfg.StrOpt('neutron_ip',
               default='',
               help=_('Neutron server ip.')),
    cfg.StrOpt('service_name',
               default='physnet1',
               help=_('Service name.')),
    cfg.IntOpt('request_timeout',
               default=60,
               help=_('AC REST request timeout value.')),
    cfg.IntOpt('timeout_retry',
               default=3,
               help=_('AC REST request timeout retry count.')),
    cfg.IntOpt('token_retry',
               default=3,
               help=_('AC token retry count.'))
]

cfg.CONF.register_opts(HUAWEI_AC_DRIVER_OPTS, "ml2_huawei_ac")
