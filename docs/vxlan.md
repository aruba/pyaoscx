# VXLAN

The VXLAN is an encapsulation protocol that uses tunneling to stretch a Layer 2
connection over an underlying Layer 3 network.

## 1. Overview

VXLAN allows you to segment your network, similar to VLANs.  But VXLAN also
addresses the scaling limitations of VLANS by allowing tunneling Layer 2
connections over a Layer 3 Network. It can be understood as VLANS across data
centers.

In Aruba's implementation, there can only be one VXLAN per switch. That VXLAN is
associated to a physical interface, then Virtual Networks Identifiers (VNI) can
be created using that VXLAN interface.

## 2. Configuration commands (CLI)

The first step is to create a VXLAN interface and associate a network to it. (it
is recommended to use loopback interfaces, as in the example below whenever
possible)

```
(config)# interface vxlan 1
(config-vxlan-if)# no shutdown
(config)# interface loopback 1
(config-loopback-if)# ip address 1.1.1.1/24
(config)# interface vxlan 1
(config-vxlan-if)# source ip 1.1.1.1
```

Now that the VXLAN interface is configured, it is possible to add VNIs which are
the ones containing the VLANs for network segmentation.

```
(config)# interface vxlan 1
(config-vxlan-if)#  vni 1000
(config-vni)# vlan 10
```

## 3. Using PYAOSCX

The following code is an example of how to configure a VXLAN interface and add a
VNI. By default nothing is materialized to the switch, so you have to call the
`apply` method for each object you create to materialize them.

```python
from pyaoscx.session import Session
from pyaoscx.device import Device

# Create a session that represents the logical connection to the switch
session = Session(ip="192.168.0.2", version="10.04")
session.open(username="admin", password="admin")

# Create a device object, the logical representation of the hardware
device = Device(session)

# Create the vxlan interface
interface = device.interface(name="1/1/1")
interface.configure_vxlan(source_ipv4="1.1.1.1")
interface.apply()

# Create a VLAN to include into the VXLAN
vlan = device.vlan(10)
vlan.apply()

# Create the VNI
vni = device.vni(vni_id=1000, interface=interface, vlan=vlan)
vni.apply()

# Do not forget to close the session
session.close()
```
