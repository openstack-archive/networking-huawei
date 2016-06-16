====================
Agile Controller(AC)
====================

Agile Controller(AC) is a server-based software for transforming data center
and enterprise IT infrastructure into centrally-controlled, virtualized,
service-oriented networks.

Tightly integrated with OpenStack cloud computing technology and SDN-ready
networking products, the SDN Controller provides unified access, security, and
performance management across the entire network. Visual interfaces simplify
provisioning and management processes, and open APIs let you customize
management and performance capabilities to meet the specific needs of your
organization.

Migrate towards the future of enterprise IT with a more agile, responsive,
and easier-to-manage network.

The networking-huawei plugin contains Agile Controller driver, which
allows OpenStack to communicate with the Agile Controller.

Features
--------

* Support CRUD operations for ML2 resources like port, subnet and network.
* Support Security group functionality.
* Support router functionality.

Installation
------------

1. If using DevStack deployment, add networking huawei plugin to
   the *local.conf/localrc* file before starting.

      ::

          [[local|localrc]]
          disable_service n-net
          enable_service neutron q-svc q-dhcp q-l3 q-meta
          enable_plugin networking-huawei https://github.com/openstack/networking-huawei.git master
          enable_service huawei-ac

2. Deploying on already running OpenStack Controller
     a. Update /etc/neutron/plugins/ml2/ml2_conf.ini for L2 plugin.

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

     b. Update /etc/neutron/neutron.conf for L3 router plugin.

      ::

            [DEFAULT]
            service_plugins = huawei_ac_router

