"""
Deploy a container on an AOS-CX switch using pyaoscx.

This workflow creates a VLAN, an isolated network, and deploys a container
image onto the switch. It demonstrates both the granulated (object-oriented)
and factory approaches.

Preconditions:
    - Switch REST API is enabled (https-server rest access-mode read-write).
    - The container image is hosted on an HTTP server reachable from the
      switch via the specified VRF.
    - Use the correct API version for container support:
        * v10.17 for 8325 (GL.10.19)
        * v10.18 for 6300 (FL.10.18)
      Login is served by v10.09 only, hence LOGIN_API_VERSION below; the
      session cookie it returns is accepted by the newer versions.

Usage:
    1. Update the CONFIGURATION section below for your environment.
    2. Run: python3 deploy_container.py
"""

import urllib3

from pyaoscx.session import Session
from pyaoscx.vlan import Vlan
from pyaoscx.container_isolated_network import ContainerIsolatedNetwork
from pyaoscx.container import Container

# =============================================================================
# CONFIGURATION — Update these for your environment
# =============================================================================
SWITCH_IP = "10.200.20.16"
API_VERSION = "10.18"       # "10.17" for 8325, "10.18" for 6300
LOGIN_API_VERSION = "10.09"
USERNAME = "admin"
PASSWORD = ""

IMAGE_URL = "http://10.93.201.106:8000/log_agent.img"
VLAN_ID = 10
VLAN_NAME = "container_vlan_10"
NET_NAME = "net10"
NET_IP = "192.168.10.99/24"
CTR_NAME = "log_agent"
VRF_NAME = "mgmt"           # VRF the switch uses to fetch IMAGE_URL
STARTUP_TIMEOUT = 300
# =============================================================================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    """Deploy and verify the container; return a process exit status."""
    # --- Connect to the switch ---
    s = Session(SWITCH_IP, API_VERSION, login_api=LOGIN_API_VERSION)
    s.open(USERNAME, PASSWORD, use_proxy=False)

    try:
        # --- APPROACH 1: GRANULATED (Object-Oriented) ---

        # Step 1: Create a VLAN for the container network
        print(f"Creating VLAN {VLAN_ID}...")
        vlan = Vlan(s, VLAN_ID, name=VLAN_NAME)
        vlan.apply()
        print(f"  VLAN {VLAN_ID} ready.")

        # Step 2: Create the isolated network
        print(f"Creating isolated network '{NET_NAME}'...")
        net = ContainerIsolatedNetwork(
            s, NET_NAME,
            vlan=vlan,
            ipv4_address=NET_IP,
        )
        net.apply()
        print(f"  Isolated network '{NET_NAME}' ready.")

        # Step 3: Deploy the container
        print(f"Creating container '{CTR_NAME}'...")
        ctr = Container(
            s, CTR_NAME,
            image_location=IMAGE_URL,
            isolated_network=net,
            vrf=VRF_NAME,
            allow_unsigned_image=True,
            enable=True,
        )
        ctr.apply()
        print(f"  Container '{CTR_NAME}' created.")

        # Step 4: Wait for the image to download and the container to start
        print("Waiting for the container to become operational...")
        ok, status, reason = ctr.wait_until_operational(
            timeout=STARTUP_TIMEOUT,
            callback=lambda st, why: print(f"  status: {st} {why}"),
        )
        if not ok:
            print(f"  Container did not start: {status} {reason}")
            return 1
        print(f"  Container '{CTR_NAME}' operational.")

        # Step 5: Verify
        print("\nVerifying...")
        net.get()
        print(f"  Isolated network: {net}")
        ctr.get()
        print(f"  Container: {ctr}")
        print(f"  Container enabled: {ctr.enable}")

        # List all containers on the switch
        print("\nAll containers on switch:")
        all_containers = Container.get_all(s)
        for name in all_containers:
            print(f"  - {name}")

        # --- APPROACH 2: FACTORY (shown for reference, commented out) ---
        # from pyaoscx.pyaoscx_factory import PyaoscxFactory
        # factory = PyaoscxFactory(s)
        # vlan = factory.vlan(VLAN_ID, VLAN_NAME)
        # net = factory.container_isolated_network(
        #     NET_NAME, vlan_id=VLAN_ID, ipv4_address=NET_IP,
        # )
        # ctr = factory.container(
        #     CTR_NAME,
        #     image_location=IMAGE_URL,
        #     isolated_network_name=NET_NAME,
        #     vrf=VRF_NAME,
        #     allow_unsigned_image=True,
        #     enable=True,
        # )

    except Exception as error:
        print(f"Error: {error}")
        return 1

    finally:
        s.close()
        print("\nDone.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
