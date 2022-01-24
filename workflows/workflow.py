from pyaoscx.session import Session
from pyaoscx.pyaoscx_factory import PyaoscxFactory
from pyaoscx.vlan import Vlan
from pyaoscx.interface import Interface

# There are two approaches to workflows, both using the session.
version = "10.04"
switch_ip = "172.25.0.2"
s = Session(switch_ip, version)
s.open("admin", "admin")

# Try block is used so that session closes even on error.
try:
    # APPROACH 1: OPEN GRANULATED APPROACH
    # VLAN
    # Create Vlan object -- Not yet materialized
    vlan100 = Vlan(s, 100, name="VLAN 100", voice=True)

    # Since object is not materialized, performs
    # a POST request -- This method internally
    # makes a GET request right after the POST
    # Obtaining all attributes VLAN related
    vlan100.apply()

    # Now let's create another object, that we know already exists
    # inside of the Switch
    vlan1 = Vlan(s, 1)
    # Perform a GET request to obtain all data and materialize object
    vlan1.get()
    # Now, we are able to modify the objects internal attributes
    vlan1.voice = True
    # Apply changes
    changed = vlan1.apply()
    # If changed is True, a PUT request was done and object was modified

    vlan100.description = "New description, changed via pyaoscx SDK"
    vlan100.apply()
    # Now vlan100 contains the description attribute
    print("VLAN 100 description {0}".format(vlan100.description))

    # ===========================================================
    # ===========================================================
    # ===========================================================

    # APPROACH 2: IMPERATIVE FACTORY APPROACH
    # VLAN
    # Create Factory object, passing the Session Object
    factory = PyaoscxFactory(s)

    # Create Vlan object
    # If vlan is non-existent, Factory instantly creates it
    # inside the switch device
    vlan200 = factory.vlan(200, "NAME200")

    # Now the granulated approach could still be used.
    # Or an imperative method too

    # ===========================================================
    # ===========================================================
    # ===========================================================

    # More complex example using the OPEN GRANULATED APPROACH
    # Create an Interface object

    lag = Interface(s, "lag1")
    lag.apply()

    # Create a Vlan object

    vlan_1 = Vlan(s, 1)
    # In this case, now that the VLAN exists within the Switch,
    # a GET request is called to obtain the VLAN's information.
    # The information is then added to the object as attributes.
    vlan_1.get()
    # Interfaces/Ports added to LAG
    port_1_1_11 = Interface(s, "1/1/11")
    port_1_1_11.get()
    # Make changes to configure LAG as L2
    lag.admin = "down"
    lag.routing = False
    lag.vlan_trunks = [vlan_1]
    lag.lacp = "passive"
    lag.other_config["mclag_enabled"] = False
    lag.other_config["lacp-fallback"] = False
    lag.vlan_mode = "native-untagged"
    lag.vlan_tag = vlan_1
    # Add port as LAG member
    lag.interfaces.append(port_1_1_11)

    # Apply changes
    lag.apply()

    # ===========================================================
    # ===========================================================
    # ===========================================================

    # Same complex example using the IMPERATIVE FACTORY APPROACH
    # PLUS USING IMPERATIVE METHODS

    # Create the Interface object
    lag2 = factory.interface("lag2")
    modified = lag2.configure_l2(
        description="Created using imperative method",
        admin="up",
        vlan_mode="native-untagged",
        vlan_tag=1,
        trunk_allowed_all=True,
        native_vlan_tag=True,
    )
    # If modified is True, a PUT request was done and object was modified

except Exception as error:
    print("Ran into exception: {0}. Closing session.".format(error))

finally:
    # At the end, the session MUST be closed
    s.close()
