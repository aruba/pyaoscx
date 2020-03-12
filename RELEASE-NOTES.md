# 1.0.0

## Notable Changes
* This is the initial release for the AOS-CX Python libraries, example sample data, and workflows.
* For this release, it is recommended to only utilize the v1 API due to current issues that are listed in the Known Issues section.

## Known Issues
 * Issue with v10.04 REST API prevents POST and PUT to create or update interfaces.  This affects workflows:
    * configure_acl.py and cleanup_acl.py
    * configure_loop_protect.py and cleanup_loop_protect.py
    * configure_evpn_vxlan.py and cleanup_evpn_vxlan.py
    * configure_access_security.py and cleanup_access_security.py
    * configure_l2_l3_lags.py and cleanup_l2_l3_lags.py
    * configure_l2_l3_vlans.py and cleanup_l2_l3_vlans.py
    * configure_qos.py and cleanup_qos.py
    * configure_vrf_vlan_access.py, configure_vrf_vlan_trunk.py, and cleanup_vrf_vlan.py                
    
 * Issue with v10.04 VSX REST API prevents VSX instances from being created and deleted.  This affects the configure_vsx.py workflow.
 
 * Issue with v10.04 REST API to DELETE User Based Tunneling Zones.  This affects the cleanup_access_security.py