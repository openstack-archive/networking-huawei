============
Installation
============

1. General
----------

This guide will help you to install networking_huawei plugin for OpenStack to
communicate with Huawei SDN Controllers.

This guide does not necessarily cover all OpenStack installation steps
especially at production scale. Plugin only supported for OpenStack Liberty
and master versions.

There must be an Huawei Controller running in a machine which is reachable
from the Neutron Server.

2. Networking-huawei plugin installation
----------------------------------------

2.1 DevStack deployment
~~~~~~~~~~~~~~~~~~~~~~~

     1. Download the DevStack.
         *"git clone https://git.openstack.org/openstack-dev/devstack"*.
     2. Create user "stack".
         *"devstack/tools/create-stack-user.sh; su stack"*.
     3. Move inside the devstack folder.
         *"cd devstack"*.
     4. Add networking huawei plugin to the *local.conf/localrc* file.

      ::

          [[local|localrc]]
          disable_service n-net
          enable_service neutron q-svc q-dhcp q-l3 q-meta
          enable_plugin networking-huawei https://github.com/openstack/networking-huawei.git master
          enable_service huawei-ac

     5. Update the configuration for AC in *local.conf/localrc* file under
        *ml2_huawei* namespace if required.
     6. Start the DevStack *"./stack.sh"*.

2.2 Setup where OpenStack Controller is already deployed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


     1. Install the plugin first.
         *"pip install git+https://git.openstack.org/openstack/
         networking-huawei"*.

     2. Update /etc/neutron/plugins/ml2/ml2_conf.ini for L2 plugin.

      ::

            [ml2]
            type_drivers = local,vxlan
            mechanism_drivers = huawei_ac_ml2

            [ml2_type_gre]
            tunnel_id_ranges = 32769:34000

            [ml2_type_vxlan]
            vni_ranges = 65537:69999

            [huawei_ac_config]
            host = 192.167.1.10
            username = admin
            password = xxxxxx
            neutron_name = NeutronServer1
            neutron_ip = 10.10.10.10


     3. Update /etc/neutron/neutron.conf for L3 router plugin.

      ::

            [DEFAULT]
            service_plugins = huawei_ac_router

     4. Restart the neutron server service.
