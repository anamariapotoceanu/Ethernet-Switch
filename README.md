# Ethernet-Switch
## VLAN IMPLEMENTATION

- To store the switch configuration information, a dictionary `vlan_map` was used, structured as `interface_index -> (interface_type, vlan_id)`.

- In the `load_configuration_from_file` function, `switch_priority` was stored as a global variable, as it is required for STP implementation.  
  The check for whether a port is `trunk` or `access` was done using the `vlan_id` field, which may or may not be a number.

- During the implementation, the first step was to check if the `802.1Q header` was present.  
  If it was not present, it was added, and the `length` was increased by 4 units.

- If the destination MAC address is found in the MAC table, the destination port is checked to determine whether it is `trunk` or `access`:
  - For `trunk` ports, a check was performed to ensure the port was not in the `BLOCKING` state before forwarding packets.  
    Adding the header at the beginning allowed the packet to be sent in the correct format.
  - If the port is of type `access`, it must belong to the same VLAN, meaning the `vlan_id` of the destination must match that of the source.  
    Additionally, the `802.1Q header` is removed.

- If the MAC address is not found in the MAC table, the packet is sent to all existing interfaces except the one from which it was received.  
  Each interface type is verified before forwarding.

- The last case is `broadcast`, where the packet is sent to all ports.  
  Before forwarding, the same checks are performed to determine whether the destination port is `trunk` or `access`.

## STP IMPLEMENTATION

- For STP implementation, a dictionary (`states = {}`) was used to store the state of each port, specifically whether it is in `BLOCKING` or `LISTENING` mode.

- In the `create_bpdu_packet` function, the specific frame for `BPDU packets` was created.  
  All required fields, including `dest_mac`, the MAC address used to identify a BPDU packet, were concatenated.

- In the `initialize_ports()` function, `trunk` ports were initially set to `BLOCKING`, and each port behaved as a `root_bridge` at the beginning.  
  Thus, the port states were changed to `LISTENING`.

- The `process_bpdu_packet` function is responsible for handling received `BPDU` packets. The pseudocode from the assignment was followed:
  - The packet information is evaluated, and if a `root_bridge` with a lower ID is detected, it must be updated.  
    A better `root_bridge` is found if the condition `bpdu_root_bridge_ID < root_bridge_ID` is met.
  - If the switch was previously the `root_bridge`, its ports must be set to `BLOCKING`, as another switch has become the `root_bridge`.
  - The new `root` state is set to `LISTENING` so that it can process packets.
  - With the updated information, the switch must forward `BPDU` packets to all its `trunk` ports.  
    The sender is the current switch itself.
  - If the `root_bridge_ID` remains the same (`BPDU.root_bridge_ID == root_bridge_ID`), a check is performed to determine if a better path to the `root` exists.
  - If the `BPDU` packet was sent from the same switch, the port is set to `BLOCKING` to prevent loops.
  - The final case is when the switch is itself the `root_bridge`, meaning all its ports are set to `LISTENING` to process packets.
