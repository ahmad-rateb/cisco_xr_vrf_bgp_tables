"""
Collects best IP networks from a given VRF's BGP tables on a CiscoXR router

Script Operation:
    - Connects to a CiscoXR router with Netmiko
    - Collects outputs of "show bgp vrf x ipv4|6 unicast"
    - Parses the collected outputs with RegEx to find best BGP networks
    - Stores each NLRI by its attributes; network-id, next-hop, as-path-list
    - Writes best networks and their attributes to disk in JSON format

Input Arguments:
    - `--username` for Username
    - `--device` for CiscoXR Hostname/IP
    - `--vrf` for VRF name
    - `--log` Enable informational-level logging (optional)

User Input:
    - Password

Script Output:
    - JSON files for parsed IPv4|6 NLRIs and their attributes

Preset Values:
    - read_timeout in send_command() function is set to 120 seconds
"""

from typing import Tuple, List, Dict, Optional, Iterator
from getpass import getpass
from argparse import ArgumentParser
import logging
import json
import sys
import re

from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko import ConnectHandler

# Type hints aliases
ParsedBGPEntry = Tuple[str, str, List[str]]


def add_user_args() -> ArgumentParser:
    """Sets CLI arguments and returns the parser object"""

    parser = ArgumentParser()
    parser.add_argument("--username", help="Username", required=True)
    parser.add_argument("--device", help="Device Hostname/IP", required=True)
    parser.add_argument("--vrf", help="VRF", required=True)
    parser.add_argument("--log", help="Enable info logging", required=False, action="store_true")
    return parser


def parse_user_args() -> Tuple[str, str, str, str, Optional[bool]]:
    """Parse loaded CLI arguments and return their values"""

    parser = add_user_args()
    parsed_args = parser.parse_args()

    username: str = parsed_args.username
    password: str = getpass("Password: ")
    device: str = parsed_args.device
    vrf: str = parsed_args.vrf
    logging_status: Optional[bool] = parsed_args.log

    return username, password, device, vrf, logging_status


def set_info_logging(logging_status: Optional[bool]) -> None:
    """Enable/Disable informational-level logging based on CLI argument"""

    if logging_status:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.disable()


def netmiko_login_exception_handler(func):
    """Decorator function for handling login exceptions"""
    def wrapper(*args):
        try:
            return func(*args)
        except NetmikoAuthenticationException:
            sys.exit("\nWrong username or password\n")
        except NetmikoTimeoutException:
            sys.exit("\nCouldn't connect to provided Hostname/IP\n")
    return wrapper


@netmiko_login_exception_handler
def collect_bgp_tables(xr_login_data: Dict[str, str], vrf: str) -> List[str]:
    """
    Connects to a CiscoXR router and returns raw BGPv4|6 tables of a given VRF

    Parameters:
        xr_login_data: Dictionary of host information used by netmiko
        vrf: VRF name as string

    Returns:
        raw_bgp_tables: A list of two multiline strings;
            Index 0: BGPv4 table as returned by "show bgp vrf x ipv4 unicast"
            Index 1: BGPv6 table as returned by "show bgp vrf x ipv6 unicast"
    """

    logging.info(f"Establishing connection with {xr_login_data['host']}")
    raw_bgp_tables = []
    with ConnectHandler(**xr_login_data) as net_connect:
        for ip_ver in ("IPv4", "IPv6"):
            logging.info(f"Collecting {ip_ver} BGP table for VRF {vrf}")
            command = f"show bgp vrf {vrf} {ip_ver.lower()} unicast"
            raw_bgp_table = net_connect.send_command(command, read_timeout=120)
            raw_bgp_tables.append(raw_bgp_table)
    return raw_bgp_tables


def parse_bgp_table_by_regex(raw_bgp_table: str) -> List[Tuple[str, ...]]:
    r"""
    Parses BGP table by two RegEx patterns:
        - Pattern 1 where status code ">" on the same line as the network
        - Pattern 2 where status code ">" not on the same line as the network

    Parameters:
        raw_bgp_table: A multiline string of "show bgp vrf x ipv4|6 unicast"

    Example:
        parse_bgp_table_by_regex('''
            *>i0.0.0.0/0          192.168.31.40         100    0 64512 65000 ?
            * i                   192.168.31.41         100    0 64512 65000 ?
            * i10.0.8.184/29      192.168.31.48    0    100    0 64512 ?
            *>                    192.168.74.17    0           0 64512 ?
            <omitted>

            Processed 62 prefixes, 231 paths''')

    Returns:
        A list of tuples, each has best NLRI attributes, NLRI and next-hop:
            [
                ('*>i0.0.0.0/0 192.168.31.40 0 64512 65000 ?',
                 '0.0.0.0/0',
                 '192.168.31.40'),
                ('* i10.0.8.184/29 192.168.31.48 0 64512 ?\n
                  *>               192.168.74.17 0 64512 ?',
                 '10.0.8.184/29',
                 '192.168.74.17'),
                 ...
            ]
    """

    # The \n* is used instead of \n? to workaround extra erraneous empty lines
    # within the extracted BGP table as captured sometimes by netmiko.
    regex_1 = r"\*>(?:i|\s)([0-9.a-f:]+/\d+)\n*.*?([0-9.a-f:]+)\n*.*"
    regex_2 = r"\*\s(?:i|\s)([0-9.a-f:]+/\d+)(?:.*\n*)+?\*>.*?([0-9.a-f:]+)\n*.*"
    regex = f"({regex_1}|{regex_2})"
    best_nlri_pattern = re.compile(regex)
    matches_iter = best_nlri_pattern.finditer(raw_bgp_table)
    matches = list(map(lambda match: tuple(filter(None, match.groups())), matches_iter))
    matches_count = len(matches)

    # Find last line location/index which contains total num of prefixes
    last_line_index = raw_bgp_table.rfind("Processed")

    # Find how many networks parsed by RegEx against what was given
    if matches_count:
        total_nets = raw_bgp_table[last_line_index:].split(" ")[1]
        logging.info(f"RegEx matches: {matches_count} out of {total_nets}")
    else:
        logging.info("BGP Address-Family isn't configured or empty BGP table")

    return matches


def parse_entry_of_bgp_table(bgp_table_entry: Tuple[str, ...]) -> ParsedBGPEntry:
    r"""
    Parse a given entry of the BGP table

    Parameters:
        bgp_table_entry: Tuple of three strings:
            - String that contains best NLRI attributes
            - NLRI
            - Next-hop address

    Example 1:
        parse_entry_from_bgp_table(
            ('*>i0.0.0.0/0 192.168.31.40 0 64512 65000 ?',
             '0.0.0.0/0',
             '192.168.31.40')
        )
    Example 2:
        parse_entry_from_bgp_table(
            ('* i10.0.8.184/29 192.168.31.48 0 64512 ?\n
              *>               192.168.74.17 0 64512 ?',
             '10.0.8.184/29',
             '192.168.74.17')
        )

    Returns:
        A tuple of NLRI, next-hop & as-path-list:
            Example 1: ('0.0.0.0/0', '192.168.31.40', ['64512', '65000', '?'])
            Example 2: ('10.0.8.184/29', '192.168.74.17', ['64512', ?'])
    """

    # AS-Path list has a fixed location, always at last line and always starts
    # from character position 63.
    # The '\n' may happen in various locations within the string
    raw_nlri_attributes, nlri, next_hop = bgp_table_entry
    best_nlri_attributes_line = raw_nlri_attributes.split('\n')[-1]
    aspath_list = best_nlri_attributes_line[63:].split(" ")
    return (nlri, next_hop, aspath_list)


def map_nlri_to_attributes(parsed_bgp_entries: Iterator[ParsedBGPEntry]) -> Dict:
    """Map each parsed NLRI to its Next-Hop and AS-Path list"""

    nlri_to_attributes = {}
    for nlri, next_hop, aspath_list in parsed_bgp_entries:
        nlri_to_attributes[nlri] = {'Next-Hop': next_hop, 'AS-Path': aspath_list}
    return nlri_to_attributes


def best_nlri_attributes(raw_bgp_table: str, ip_ver: str) -> Dict:
    """
    Parses a raw BGP table to map each NLRI to its best attributes via a dict
    and returns that dict
    """

    logging.info(f"Parsing {ip_ver} BGP table")
    best_bgp_entries = parse_bgp_table_by_regex(raw_bgp_table)
    parsed_bgp_entries = map(parse_entry_of_bgp_table, best_bgp_entries)
    return map_nlri_to_attributes(parsed_bgp_entries)


def write_to_disk(device: str, vrf: str, ip_ver: str, nlri_attributes: Dict):
    """
    Convert IPv4|6 NLRIs<>Attributes to JSON and write them to disk
    """

    if nlri_attributes:
        file_name = f"{device}_{vrf}_{ip_ver}_bgp_table.json"
        with open(file_name, "w", encoding="utf-8") as output_file:
            json.dump(nlri_attributes, output_file)


def main():
    """Main Function"""

    # Parse CLI args
    username, password, device, vrf, logging_status = parse_user_args()

    # Enable/Disable informational-level logging
    set_info_logging(logging_status)

    # Prepare login data as required by Netmiko
    xr_login_data = {
        "device_type": "cisco_xr",
        "host": device,
        "username": username,
        "password": password,
    }

    # Connect to CiscoXR router and collect the BGP tables for the given VRF
    raw_bgp4_table, raw_bgp6_table = collect_bgp_tables(xr_login_data, vrf)

    # Parse BGP tables then map each NLRI to its best attributes
    ipv4_nlri_attributes = best_nlri_attributes(raw_bgp4_table, "IPv4")
    ipv6_nlri_attributes = best_nlri_attributes(raw_bgp6_table, "IPv6")

    if not (ipv4_nlri_attributes or ipv6_nlri_attributes):
        sys.exit("\nNo addresses found in IPv4 nor IPv6 BGP tables\n")

    # Convert the IPv4|6 NLRIs-to-attributes dict to JSON and write to disk
    logging.info("Writing results to disk")
    write_to_disk(device, vrf, "IPv4", ipv4_nlri_attributes)
    write_to_disk(device, vrf, "IPv6", ipv6_nlri_attributes)


if __name__ == "__main__":
    main()
