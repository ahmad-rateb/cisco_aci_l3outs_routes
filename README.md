# Cisco ACI - L3Outs Routes Collector

Collects routable prefixes via each L3Out in a given Tenant:VRF. By having routes received-from/routed-via each L3Out, they can be used as External Networks in the L3Out's External EPG.

## Input Arguments

- `--username` for Username
- `--device` for Cisco APIC Hostname/IP
- `--tenant` for Tenant name
- `--vrf` for VRF name
- `--log` Enable informational-level logging (optional)

## User Input

- Password

## Script Output

- JSON file with APIC:Tenant:VRF:L3Out:RIB details

## Script Operation

- Connects to an APIC and provides a handle to its REST API
- Checks whether provided Tenant and VRF exist
- GETs all L3Outs attached to the VRF
- GETs L3Outs' Node-IDs
- Loads L3Outs' Node-IDs by their connected interfaces
- Downloads and Parses the Tenant:VRF Routing Table as follows
    1) Excludes Null0, Local (/32 or /128 or Broadcast), Loopback routes
    2) Stores routes with their exit-interfaces
    3) Identifies each route's L3Out via the route's exit-interface

## Preset Values

- Timeout for HTTP login/logout requests set to 10 seconds
- Timeout for downloading a Class's Managed Objects set to 60 seconds

## Required Python Modules

- requests
- pytricia

## Python Modules Installation

```bash
$ pip3 install -r requirements.txt
```

## How to use

Run the script and provide the arguments followed by the Password as mentioned in the 'Input Arguments' and 'User Input' sections above

```bash
$ python3 cisco_aci_l3outs_routes.py --username your_username --device hostname_or_ip --tenant tenant_name --vrf vrf_name [--log]
Password:
```

> Script was developed in Python 3.10. Minimum required version is Python 3.7.
