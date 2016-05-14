============
Installation
============

1. General
----------

This guide will help you to install networking_huawei plugin for openstack to communicate with Huawei Agile Controller 2.0.

This guide does not necessarily cover all OpenStack installation steps especially at production scale. Plugin only supported for OpenStack Liberty and master versions.

There must be an Agile Controller 2.0 running in a machine which is reachable from the Neutron Server.

2. Networking-huawei plugin installation
----------------------------------------

2.1 DevStack deployment
~~~~~~~~~~~~~~~~~~~~~~~

     1. Download the DevStack *"git clone https://git.openstack.org/openstack-dev/devstack"*.
     2. Create user stack *"devstack/tools/create-stack-user.sh; su stack"*.
     3. Move inside the DevStack *"cd devstack"*.
     4. Add networking huawei plugin to the *local.conf/localrc* file *"enable_plugin networking-huawei https://github.com/openstack/networking-huawei.git master"*.

      ::

          [[local|localrc]]
          disable_service n-net
          enable_service neutron q-svc q-agt q-dhcp q-l3 q-meta
          enable_plugin networking-huawei https://github.com/openstack/networking-huawei.git master

     5. Update the configuration for AC in *local.conf/localrc* file under *ml2_huawei* namespace.
     6. Else, download the plugin code *"git clone https://github.com/openstack/networking-huawei.git"* and copy *local.conf.sample.controller* file to *devstack* folder and rename it as *local.conf*.
     7. Update the *etc/neutron/huawei_ac_config.ini* file with host, port and other AC configurations.
     8. Start the DevStack *"./stack.sh"*.

2.2 Setup where OpenStack Controller is already deployed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


     1. Install the plugin *"pip install git+git://git.openstack.org/openstack/networking-huawei"*.

     2. Update /etc/neutron/plugins/ml2/ml2_conf.ini for L2 plugin.

      ::

            [ml2]
            type_drivers = local,vxlan
            mechanism_drivers = huawei_ac_ml2

            [ml2_type_gre]
            tunnel_id_ranges = 32769:34000

            [ml2_type_vxlan]
            vni_ranges = 65537:69999

            [ml2_huawei]
            host = 192.167.1.10
            username = admin
            password = Rc9xv1SFCfoS+7wmfNS7pQ==

            [ovs]
            integration_bridge = br-int
            tunnel_id_ranges = 65537:69999
            tenant_network_type = vxlan
            enable_tunneling = true
            tunnel_type = vxlan

     3. Restart the neutron server service.