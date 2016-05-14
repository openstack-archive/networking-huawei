===============================
Networking Huawei
===============================

Neutron plugin to interact with Agile Controller(AC) 2.0 and OpenStack Neutron.

The Huawei Agile Controller 2.0 allows next-generation networks to follow SDN principles throughout the engineering process through the provision of network services, policy
orchestration, and management functionality via the Open Services Gateway initiation (OSGi) framework and Representational State Transfer (REST) API interface capabilities, that allow service applications to employ network capabilities through their defined interfaces. The result is that the Agile Controller 2.0 enables the orchestration of network-wide resources in support of application services.

The Agile Controller 2.0 converges management, policy, and control plane logic into a single program. By removing the restrictions of the physical network, the Agile Controller 2.0 achieves the following:

* The Management Plane provides a holistic view of the virtual network topology for the purpose of providing uniform control and visibility for overlay, underlay, and tenant-based applications, as well as the logical and physical networks.
* The Policy Plane arranges network services automatically, using the End Point Group (EPG) model and logical network language. The Agile Controller 2.0 works with mainstream cloud plat-forms for implementing application-oriented network functions and opening network services based on subnet, router, FwACL, SNAT, and IPSec VPN parameters.
* The Control Plane interacts with the overlay networks and deploys in uplift or sinking mode, working with the cloud platform to obtain computing resources, and works with servers for controlling virtualization awareness and the management of the Address Resolution Protocol (ARP) cache and ingress replication tables.

General
-------

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/networking-huawei
* Source: http://git.openstack.org/cgit/networking-huawei/networking-huawei
* Bugs: http://bugs.launchpad.net/networking-huawei

Features
--------

* Network, Subnet and Port creation, update and deletion.
* Security group and rules handling.
