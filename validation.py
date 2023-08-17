import configparser
import ipaddress
import os
import re

def read_config(config_file):
    """
    Read and parse the configuration file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        tuple: A tuple containing system path, victim MAC address, victim IP address,
               gateway MAC address, gateway IP address, network interface and attacker MAC address.
    """
    config = configparser.ConfigParser()
    config.read(config_file)
    sys_path = config['Network']['Sys Path']
    victim_mac = config['Network']['Victim MAC']
    victim_ip = config['Network']['Victim IP']
    gateway_mac = config['Network']['Gateway MAC']
    gateway_ip = config['Network']['Gateway IP']
    interface = config['Network']['Interface']
    attacker_mac = config['Network']['Attacker MAC']
    
    return sys_path, victim_mac, victim_ip, gateway_mac, gateway_ip, interface, attacker_mac

def validate_ip(ip_str):
    """
    Validate if the given string is a valid IPv4 address.

    Args:
        ip_str (str): IP address string.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_mac(mac_str):
    """
    Validate if the given string is a valid MAC address.

    Args:
        mac_str (str): MAC address string.

    Returns:
        bool: True if the string is a valid MAC address, False otherwise.
    """
    regex = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(regex, mac_str) is not None

def validate_sys_path(path_str):
    """
    Validate if the given system path exists.

    Args:
        path_str (str): System path string.

    Returns:
        bool: True if the path exists, False otherwise.
    """
    if not os.path.exists(path_str):
        return False
    return True

