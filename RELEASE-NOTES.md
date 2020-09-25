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
