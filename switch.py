#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Dictionarul vlan_map va avea ca si cheie indexul interfetei, iar ca valoare (tip, id_vlan)
vlan_map = {}
MAC_table = {}
states = {}
switch_priority = None
own_bridge_ID = None
root_bridge_ID = None
root_path_cost = 0
root_port = None

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

# Functie pentru salvarea configuratiei switch-ului din fisier
def load_configuration_from_file(switch_id, interfaces):
    global switch_priority
    filename = f"configs/switch{switch_id}.cfg"

    with open(filename, 'r') as f:
        lines = f.readlines()

    # Retinem intr-o variabila globala prioritatea switch-ului
    switch_priority = int(lines[0].strip())
   
    for line in lines[1:]:
        line = line.strip()
        parts = line.split()
        # Retinem numele interfetei si id-ul vlan-ului
        interface_name = parts[0]
        vlan_id_string = parts[1]

        # In cazul in care id-ul este un numar, inseamna ca avem port de tip 'access'
        if vlan_id_string.isdigit():
            vlan_id = int(vlan_id_string)

            # Pentru fiecare interfata, salvam in dictionar (tip, id_vlan)
            for i in interfaces:
                if get_interface_name(i) == interface_name:
                    vlan_map[i] = ('access', vlan_id)

        elif vlan_id_string == "T":
            for i in interfaces:
                if get_interface_name(i) == interface_name:
                    vlan_map[i] = ('trunk', None)

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# In cazul in care switch-ul este root, se trimite un pachet BPDU la fiecare secunda
def send_bdpu_every_sec():
    global root_bridge_ID
    while True:
        if own_bridge_ID == root_bridge_ID:
            for port in vlan_map:
                root_bridge_ID = own_bridge_ID
                sender_bridge_ID = own_bridge_ID
                sender_path_cost = 0
                # Extragem tipul portului, folosind dictionarul vlan_map
                port_type, _ = vlan_map.get(port)
                if port_type == 'trunk':
                    data = create_bpdu_packet(root_bridge_ID, sender_bridge_ID, sender_path_cost)
                    send_to_link(port, len(data), data)
        time.sleep(1)

# Functie pentru crearea unui pachet BPDU
def create_bpdu_packet(root_bridge_id, sender_bridge_id, root_path_cost):

    # Destinatia MAC specifica pentru un pachet BPDU
    bpdu_mac = '01:80:c2:00:00:00'
    # Se foloseste functia get_switch_mac pentru a extrage adresa MAC a switch-ului
    switch_mac = ':'.join(f'{b:02x}' for b in get_switch_mac())
    dst_mac = bytes.fromhex(bpdu_mac.replace(':', ''))
    src_mac = bytes.fromhex(switch_mac.replace(':', ''))

    llc_length = 34
    llc_header = struct.pack('!BBB', 0x42, 0x42, 0x03)
    flags = 0x00
    port_id = 1
    message_age = 0
    max_age = 20
    hello_time = 2
    forward_delay = 15
    bpdu_header = struct.pack('!I', 0)
   
    bpdu_config = struct.pack(
        '!BQIQ5H', flags, root_bridge_id, root_path_cost, sender_bridge_id, port_id, message_age,
        max_age, hello_time, forward_delay
    )
    
    # Se concateneaza campurile pentru a obtine un packet BPDU
    bpdu_frame = dst_mac + src_mac + llc_length.to_bytes(2, byteorder='big') + llc_header + bpdu_header + bpdu_config
    return bpdu_frame

# Functie pentru initializarea porturilor
def initialize_ports():
    global own_bridge_ID, root_bridge_ID, root_path_cost

    # Se seteaza pe 'BLOCKING' porturile de tip 'trunk'
    for port in vlan_map:
        port_type, _ = vlan_map.get(port)
        if port_type == 'trunk':
            states[port] = 'BLOCKING'
   
    own_bridge_ID = switch_priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    # Daca portul devine root_bridge, toate porturile se seteaza pe 'LISTENING'
    if own_bridge_ID == root_bridge_ID:
        for port in vlan_map:
            states[port] = 'LISTENING'

# Functie pentru procesarea unui pachet BPDU, folosind pseudocodul din enuntul temei
def process_bpdu_packet(interface, data):
    global root_bridge_ID, root_path_cost, root_port

    # Extragem informatiile necesare din pachetul primit
    bpdu_root_bridge_ID, bpdu_sender_path_cost, bpdu_sender_bridge_ID = struct.unpack('!QIQ', data[22 : 42])

    # Se gaseste un root_bridge mai apropiat
    if bpdu_root_bridge_ID < root_bridge_ID:

        if own_bridge_ID == root_bridge_ID:
            for port in vlan_map:
                port_type, _ = vlan_map.get(port)
                if port_type == 'trunk' and port != root_port:
                    states[port] = 'BLOCKING'
        
        # Se seteaza noile valori pentru root_bridge
        root_bridge_ID = bpdu_root_bridge_ID
        root_path_cost = bpdu_sender_path_cost + 10 
        root_port = interface

        if states.get(root_port) == 'BLOCKING':
            states[root_port] = 'LISTENING'

        # Se trimit pachete pe toate porturile de tip 'trunk', folosind noile valori
        for port in vlan_map:
            port_type, _ = vlan_map.get(port)
            if port_type == 'trunk' and port != root_port:
                sender_bridge_ID = own_bridge_ID
                sender_path_cost = root_path_cost
                data = create_bpdu_packet(root_bridge_ID, sender_bridge_ID, sender_path_cost)
                send_to_link(port, len(data), data)

    # Se verifica daca exista o cale mai buna catre root_bridge si se actualizeaza
    elif bpdu_root_bridge_ID == root_bridge_ID:
        if interface == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10

        # Switch-ul are o cale mai buna catre root_bridge si se va seta starea acestuia pe 'LISTENING'
        elif interface != root_port:
            if bpdu_sender_path_cost > root_path_cost:
                states[interface] = 'LISTENING'

    elif bpdu_sender_bridge_ID == own_bridge_ID:
        states[interface] = 'BLOCKING'
    # Switch-ul este root_bridge si va permite trimiterea pachetelor pe toate porturile
    if own_bridge_ID == root_bridge_ID:
        for port in vlan_map:
            states[port] = 'LISTENING'

# Functie care verifica daca avem o adresa MAC de tip unicast
def is_unicast(mac):
    first_hex = mac.split(":")[0]
    first_octet = int(first_hex, 16)
    return (first_octet & 0x01) == 0


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    global switch_id
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    load_configuration_from_file(switch_id, interfaces)
    initialize_ports()

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)
        # Se verifica daca avem un pachet BPDU
        if dest_mac == '01:80:c2:00:00:00':
            process_bpdu_packet(interface, data)
        else:
            port_type, port_vlan_id = vlan_map.get(interface, (None, None))
            # Daca portul este setat pe 'BLOCKING', nu se poate trimite pachete
            if states.get(interface) == 'BLOCKING':
                return
            
            # Daca vlan_id este -1, inseamna ca nu exista header 802.1Q si il adaugam
            if port_type == 'access' and vlan_id == -1:
                vlan_id = port_vlan_id
                tagged_frame = data[0:12] + create_vlan_tag(port_vlan_id) + data[12:]
                length += 4
            else:
                # Daca header-ul exista, cadrul ramana neschimbat
                tagged_frame = data

            MAC_table[src_mac] = (interface, vlan_id)

            if is_unicast(dest_mac):
                if dest_mac in MAC_table:
                    dest_interface = MAC_table[dest_mac][0]
                    dest_port_type, dest_port_vlan_id = vlan_map.get(dest_interface, (None, None))
                    # Pachetul poate fi trimis atat pe porturi trunk, cat si pe porturi access
                    if (dest_port_type == 'trunk' and states.get(dest_interface) != 'BLOCKING') or (dest_port_type == 'access' and dest_port_vlan_id == vlan_id):
                        # Verificare daca se trimite pachetul pe un port trunk si nu este setat pe 'BLOCKING'
                        if dest_port_type == 'trunk' and states.get(dest_interface)!= 'BLOCKING':
                            send_to_link(dest_interface, length, tagged_frame)
                        # Daca se trimite pe un port access, se elimina header-ul 802.1Q
                        elif dest_port_type == 'access' and dest_port_vlan_id == vlan_id:
                            new_tagged = tagged_frame[0:12] + tagged_frame[16:]
                            send_to_link(dest_interface, length - 4, new_tagged)
                else:
                    # Daca adresa MAC destinatie nu se afla in tabela MAC, pachetul se va trimite pe toate porturile
                    for i in interfaces:
                        if i != interface:
                            p_type, p_vlan = vlan_map.get(i, (None, None))
                            if (p_type == 'trunk' and states.get(i) != 'BLOCKING') or (p_type == 'access' and p_vlan == vlan_id):
                                if p_type == 'trunk' and states.get(i) != 'BLOCKING':
                                    send_to_link(i, length, tagged_frame)
                                else:
                                    p_new_tagged = tagged_frame[0:12] + tagged_frame[16:]
                                    send_to_link(i, length - 4, p_new_tagged)
            else:
                # Broadcast, se trimite pachetul pe toate porturile
                for i in interfaces:
                    if i != interface:
                        p_type, p_vlan = vlan_map.get(i, (None, None)) 
                        if (p_type == 'trunk' and states.get(i) != 'BLOCKING') or (p_type == 'access' and p_vlan == vlan_id):
                            if p_type == 'trunk' and states.get(i) != 'BLOCKING':
                                send_to_link(i, length, tagged_frame)
                            else:
                                p_new_tagged = tagged_frame[0:12] + tagged_frame[16:]
                                send_to_link(i, length - 4, p_new_tagged)


        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
