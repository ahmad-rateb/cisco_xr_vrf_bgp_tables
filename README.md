# CiscoXR - VRF's BGP Tables Collector

Collects best IP networks from a given VRF's BGP tables on a CiscoXR router

## Input Arguments

- `--username` for Username
- `--device` for CiscoXR Hostname/IP
- `--vrf` for VRF name
- `--log` Enable informational-level logging (optional)

## User Input

- Password

## Script Output

- JSON files for parsed IPv4|6 NLRIs and their attributes

## Script Operation

- Connects to a CiscoXR router with Netmiko
- Collects outputs of "show bgp vrf x ipv4|6 unicast"
- Parses the collected outputs with RegEx to find best BGP networks
- Stores each NLRI by its attributes; network-id, next-hop, as-path-list
- Writes best networks and their attributes to disk in JSON format

## Preset Values

- The `read_timeout` arg in `sendcommand()` function is set to 120, i.e. connection handler will not wait more than 2 minutes for the 'show' command's output to be fully returned by CLI

## Required Python Modules

- netmiko>=4.0.0

> Netmiko of version 4.0.0+ is needed to support `read_timeout` argument in the `send_command()` function, this is much better than the traditional `delay_factor`. More details [here](https://github.com/ktbyers/netmiko/discussions/2302) and [here](https://github.com/ktbyers/netmiko/releases/tag/v4.0.0).

## Python Modules Installation

```bash
$ pip3 install -r requirements.txt
```

## How to use

Run the script and provide the arguments followed by the Password as mentioned in the 'Input Arguments' and 'User Input' sections above

```bash
$ python3 cisco_xr_vrf_bgp_tables.py --username your_username --device hostname_or_ip --vrf vrf_name [--log]
Password:
```

> Script was developed in Python 3.10. Minimum required version is Python 3.7.

## About BGP table parsing

BGP table is parsed with two Regular Expressions to capture "best" prefixes:

- RegEx 1 searches for patterns where the status code ">" and Network ID are on the same line
- RegEx 2 searches for patterns where the status code ">" not on the same line as the Network ID

The script doesn't search for the following route types:

- Suppressed routes (code "s>") as they are not advertised while their summary is advertised and thus captured
- Dampened routes (code "\*d") as dampened-routes are also suppressed from advertisement

> In IOS-XR, RIB-Failure status doesn't show up in "show bgp" table output with code "r>", but just ">", they also don't show up in the "show bgp x.x.x.x" (check [this](https://learningnetwork.cisco.com/s/question/0D53i00000gAparCAC/does-iosxr-show-ribfailure) and [this](https://community.cisco.com/t5/xr-os-and-platforms/xr-command-for-rib-failure/td-p/2835851)). Technically speaking, despite their status, they're normally advertised to other peers, so there're no reasons not to capture them (unlike the case for supressed & dampened routes).
