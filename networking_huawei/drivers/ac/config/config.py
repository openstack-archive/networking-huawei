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
               default='127.0.0.1',
               help=_('Huawei Agile Controller(AC) REST host address. '
                      'If this is not set then no HTTP requests will '
                      'be made.')),
    cfg.IntOpt('port',
               default=32102,
               help=_('Huawei Agile Controller(AC) ReST interface port'
                      ' number.')),
    cfg.StrOpt('username',
               default='huawei',
               help=_('Username to authenticate the connect to AC. '
                      'This is a mandatory field to authenticate the AC.')),
    cfg.StrOpt('password',
               default='Huawei@123',
               secret=True,  # do not expose value in the logs
               help=_('Password to authenticate the connect to AC. '
                      'This is a mandatory field to authenticate the AC.')),
    cfg.StrOpt('neutron_name',
               default='Neutron_Server1',
               help=_('Neutron server host name. This is a mandatory field.')),
    cfg.StrOpt('neutron_ip',
               default='127.0.0.1',
               help=_('Neutron server ip. This is a mandatory field.')),
    cfg.StrOpt('service_name',
               default='physnet1',
               help=_('Service name.')),
    cfg.IntOpt('request_timeout',
               default=60,
               help=_('AC HTTP request timeout value in seconds. This is an '
                      'optional parameter, default value is 60 seconds.')),
    cfg.IntOpt('timeout_retry',
               default=3,
               help=_('AC HTTP request timeout retry count. This is an '
                      'optional parameter, default retry is 3.')),
    cfg.IntOpt('token_retry',
               default=3,
               help=_('AC token retry count. This is an optional parameter, '
                      'default retry is 3.'))
]

cfg.CONF.register_opts(HUAWEI_AC_DRIVER_OPTS, "huawei_ac_config")
