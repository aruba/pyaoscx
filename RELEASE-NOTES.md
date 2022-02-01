# 2.2.0

## Notable Changes

* Added support for the following modules:
   * Queue Profile
   * OSPF
   * QOS DSCP
   * VSX (in factory)
* Added updates to Interface modules for QoS
* Added global QoS profiles, QoS trust mode
* Added address family verification to Static Route
* Updated README.md with API requirements and note about Master branch
* Various Bugfixes
   * ACE modification
   * Missing self parameter in API method
   * Fixed circular import in VRF
   * Fixed Modifying dictionary during iteration error in ACL
   * Removed certain attributes when updating an ACL entry
   * Fixed QoS and QoSDSCP modules and imperative methods
   * Fixed interface for rate data type and trust mode in QoS
   * Fixed VRF in devices with different capabilities
   * Fixed invalid GET response for non-existing Interface
   * Fixed Schedule Profile attributes when updating
   * Remove call to get() in mac.py's get_all()
   * Fixed config_attrs if calling get() without selector
   * Shorten payloads for network requests
   * Verification added for missing PoE capability
   * Fixed isl_port interface instantiation
   * Added missing import and decorator in interface module 
   * Added missing parameter to logging call in QoS


# 2.1.0

## Notable Changes

* Added support for the following modules:
   * MAC
   * QoS
   * PoE
* Added support for REST version 10.08
* Bug fixes in ACL and Interface modules
* General code quality improvements for maintainability
* netaddr was added as a dependency


# 2.0.0

## Notable Changes
**WARNING: V2 is NOT backwards compatible with v1 and earlier**
* Huge overhaul of the design - the libraries now use factories in order for the code to be more object oriented.
  Please read the [Design document](pyaoscx/DESIGN.md) file for more information.
* Removed previous workflow examples (defunct) and added /workflows/workflow.py as an example for using the new design
* Added directories for supporting files in /rest/v1 and /rest/v10_04
* Most of the previous libraries have been updated, but there are unsupported modules that are pending updates below:
   * ARP
   * Common_ops
   * EVPN
   * LLDP
   * Loop Protect
   * MAC
   * NAE
   * QoS
   * System
   * VXLAN
* Additionally, a few libraries have been migrated into other libraries:
   * bgp.py is now split between bgp_router.py and bgp_neighbor.py
   * config. py is now configuration.py
   * dhcp.py is now dhcp_relay.py
   * lag.py is now integrated into interface.py
   * ospf.py is now split between ospf_area.py, ospf_interface.py, and ospf_router.py


# 1.0.0

## Notable Changes
* Made changes to setup.py to update the PyPi information

# 0.3.0

## Notable Changes
* Added nae.py, a new module to provide functionality for interacting with NAE scripts and agents.
* Added a function 'create_first_password' to setup.py to support logging into a factory default switch and handling the mandatory password creation.

# 0.2.2

## Notable Changes
* Minor bug fix in system.py module

# 0.2.1

## Notable Changes
* Modified setup.py to mandate the Python3 requirement

# 0.2.0

## Notable Changes
Updates to the following files:

* access_security.py
* acl.py
* common_ops.py
* evpn.py
* interface.py
* lag.py
* ospf.py
* port.py
* qos.py
* vsx.py

# 0.1.2

## Notable Changes
* Fixed '_create_l3_lag_interface' to configure each member port to belong to the L3 LAG.

# 0.1.1

## Notable Changes
* None--a version-up was required due to accidentally uploading the wrong code as version 0.1.0 to PyPI and not being able to delete it nor re-use the version number.

# 0.1.0

## Notable Changes
* This is the initial release for the AOS-CX Python libraries, example sample data, and workflows.
* For this release, it is recommended to only utilize the v1 API due to current issues that are listed in the Known Issues section.

## Known Issues
 * Issue with v10.04 REST API prevents updating an Interface table entry's OSPF authentication information. This affects workflows:
    * configure_ospf.py
