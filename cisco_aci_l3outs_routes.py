"""
Collects routable prefixes via each L3Out in a given Tenant:VRF

Script Operation:
    - Connects to an APIC and provides a handle to its REST API
    - Checks whether provided Tenant and VRF exist
    - GETs all L3Outs attached to the VRF
    - GETs L3Outs' Node-IDs
    - Loads L3Outs' Node-IDs by their connected interfaces
    - Downloads and Parses the Tenant:VRF Routing Table as follows
        1) Excludes Null0, Local (/32 or /128 or Broadcast), Loopback routes
        2) Stores routes with their exit-interfaces
        3) Identifies each route's L3Out via the route's exit-interface

Input Arguments:
    - `--username` for Username
    - `--device` for Cisco APIC Hostname/IP
    - `--tenant` for Tenant name
    - `--vrf` for VRF name
    - `--log` Enable informational-level logging (optional)

User Input:
    - Password

Script Output:
    - JSON file with APIC:Tenant:VRF:L3Out:RIB details

Preset Values:
    - Timeout for HTTP login/logout requests set to 10 seconds
    - Timeout for downloading a Class's Managed Objects set to 60 seconds
"""

from typing import List, Dict, Set, Tuple, DefaultDict, Optional
from argparse import ArgumentParser
from collections import defaultdict
from ipaddress import ip_network
from getpass import getpass

import logging
import json
import sys
import re

from pytricia import PyTricia
import requests
import urllib3


class ModPyTricia(PyTricia):
    """Modified PyTricia class with a class method as an alt-constructor"""

    def __init__(self, ip_bits: int) -> None:
        """Constructor"""

        super().__init__(ip_bits)

    @classmethod
    def from_urib(cls, urib: str) -> PyTricia:
        """Instantiate PyTricia object based on uRIB version"""

        ip_bits = 32 if urib == "uribv4" else 128
        return cls(ip_bits)


class ACIConnect:
    """
    A Context Manager that handles APIC login & logout operations

    Provides two REST API GET methods
        1) GET Managed Objs by their Class
        2) GET specific Managed Object by its DN
    """

    def __init__(self, username: str, password: str, device: str) -> None:
        """Constructor"""

        self.device = device
        self.apic_cookies = {}
        self.json_creds = json.dumps({"aaaUser": {"attributes": {"name": username, "pwd": password}}})

    def __enter__(self):
        """Connect to APIC"""

        self.apic_login()
        return self

    def __exit__(self, *args) -> None:
        """Graceful logout from APIC"""

        self.apic_logout()

    @staticmethod
    def login_exceptions_handler(func):
        """Decorator function for handling HTTP/login exceptions"""
        def wrapper_func(*args):
            try:
                return func(*args)
            except requests.exceptions.ConnectionError:
                sys.exit("\nAPIC is unreachable by FQDN/IP\n")
        return wrapper_func

    @login_exceptions_handler
    def apic_login(self) -> None:
        """POST login request and update apic_cookies instance variable"""

        login_uri = f"https://{self.device}/api/aaaLogin.json"
        logging.info(f"Connecting to {self.device}")
        login_request = requests.post(login_uri, data=self.json_creds, verify=False, timeout=10)

        if login_request.status_code in (400, 404):
            sys.exit("\nBad HTTP POST login request, wrong hostname or FQDN/IP\n")
        elif login_request.status_code == 401:
            sys.exit("\nWrong username or password provided\n")
        else:
            login_reply: Dict = login_request.json()
            cookies: str = login_reply["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.apic_cookies.update({"APIC-Cookie": cookies})

    def apic_logout(self) -> None:
        """POST logout request"""

        logout_uri = f"https://{self.device}/api/aaaLogout.json"
        requests.post(logout_uri, data=self.json_creds, cookies=self.apic_cookies, verify=False, timeout=10)

    def get_managed_objs_by_class(self, mo_class: str, query_filter: Optional[str] = None) -> List[Dict]:
        """Returns a list of managed objects dictionaries of a given MO Class"""

        logging.info(f"GET Managed Objs of Class: {mo_class}")
        uri = f"https://{self.device}/api/class/{mo_class}.json"
        if query_filter:
            uri += f"?{query_filter}"
        get_request = requests.get(uri, cookies=self.apic_cookies, verify=False, timeout=60)
        get_reply: Dict = get_request.json()
        managed_objs: List[Dict] = get_reply["imdata"]
        return managed_objs

    def get_managed_objs_by_dn(self, dn: str, query_filter: Optional[str] = None) -> List[Dict]:
        """Returns a list of Managed Objects dictionaries of a given DN"""

        uri = f"https://{self.device}/api/mo/{dn}.json"
        if query_filter:
            uri += f"?{query_filter}"
        get_request = requests.get(uri, cookies=self.apic_cookies, verify=False, timeout=60)
        get_reply: Dict = get_request.json()
        managed_objs: List[Dict] = get_reply["imdata"]
        return managed_objs


class L3OutRouting:
    """
    Constructs a L3Out-routing object and then loads it by its routes.

    Below components are associated with each other:
        - L3Out<>VRF
        - Node<>L3Out
        - NodeIntf<>Node
        - NodeIntf<>L3Out
        - Route<>NodeIntf
        - Route<>L3Out
    """

    def __init__(self, tenant: str, vrf: str, aci_rest: ACIConnect) -> None:
        """Constructor"""

        self.aci_rest = aci_rest
        self.tenant = tenant
        self.vrf = vrf
        self.routes_to_l3outs = {tenant: {vrf: {"L3Out": {}}}}
        self.nodes_to_l3outs = {tenant: {vrf: {"Nodes": {}}}}
        self._vrf_in_tenant_check()

    def _vrf_in_tenant_check(self) -> None:
        """Checks whether the VRF is associated with the Tenant or not"""

        tenant_dn = f"uni/tn-{self.tenant}"
        vrf_in_tenant_dn = f"uni/tn-{self.tenant}/ctx-{self.vrf}"
        if not self.aci_rest.get_managed_objs_by_dn(tenant_dn):
            sys.exit("\nProvided tenant doesn't exist\n")
        if not self.aci_rest.get_managed_objs_by_dn(vrf_in_tenant_dn):
            sys.exit("\nProvided VRF doesn't exist\n")

    def get_routes_via_l3outs(self) -> Dict:
        """
        Performs following operations:
            - Associates L3Out(s) to their VRF(s)
            - Associates Node(s) + their connected interfaces to their L3Out(s)
            - Downloads Nodes' routing-tables
            - Maps Nodes' Routes to their associated L3Outs
            - Returns the Routes-to-L3Outs dictionary
        """

        self._load_l3outs_in_vrf()
        self._load_nodes_of_l3outs()
        self._load_nodes_by_their_connected_intfs()
        self._load_l3outs_with_routes()
        return self.routes_to_l3outs

    def _load_l3outs_in_vrf(self) -> None:
        """Updates the VRF by its L3Outs and initialize empty uRIB IPv4|6 tables for each L3Out"""

        logging.info("Loading L3Out names")
        managed_objs: List[Dict] = self.aci_rest.get_managed_objs_by_class("l3extRsEctx")
        l3out_dn_pattern = re.compile(fr"uni/tn-{self.tenant}/out-(.+)/rsectx")
        l3outs = self.routes_to_l3outs[self.tenant][self.vrf]["L3Out"]
        for managed_obj in managed_objs:
            l3out_associated_vrf: str = managed_obj["l3extRsEctx"]["attributes"]["tnFvCtxName"]
            if self.vrf == l3out_associated_vrf:
                l3out_dn: str = managed_obj["l3extRsEctx"]["attributes"]["dn"]
                l3out_match = l3out_dn_pattern.search(l3out_dn)
                if l3out_match:
                    l3out = l3out_match.group(1)
                    l3outs[l3out] = {"uribv4": set(), "uribv6": set()}
        if not l3outs:
            sys.exit("\nVRF has no L3Outs associated with it\n")

    def _load_nodes_of_l3outs(self) -> None:
        """Stores Nodes used in L3Outs and initialize empty Interfaces dictionary"""

        logging.info("Loading Nodes-IDs associated with the VRF's L3Outs")
        managed_objs: List[Dict] = self.aci_rest.get_managed_objs_by_class("l3extRsNodeL3OutAtt")
        nodes = self.nodes_to_l3outs[self.tenant][self.vrf]["Nodes"]
        for l3out in self.routes_to_l3outs[self.tenant][self.vrf]["L3Out"]:
            regex = fr"uni/tn-{self.tenant}/out-{l3out}/lnodep-.+/rsnodeL3OutAtt-\[topology/pod-[0-9]+/(.+)\]"
            node_dn_pattern = re.compile(regex)
            for managed_obj in managed_objs:
                node_dn: str = managed_obj["l3extRsNodeL3OutAtt"]["attributes"]["dn"]
                node_dn_match = node_dn_pattern.search(node_dn)
                if node_dn_match:
                    node = node_dn_match.group(1)
                    nodes[node] = {"Interfaces": {}}
        if not nodes:
            sys.exit("\nNone of the L3Outs have associated Node(s)\n")

    def _load_nodes_by_their_connected_intfs(self) -> None:
        """
        Maps each Node interface to its associated L3Out

        A Node interface can be:
            - Routed Interface
            - Routed Sub-Interface
            - SVI
        """

        nodes = self.nodes_to_l3outs[self.tenant][self.vrf]["Nodes"]
        logging.info("Loading each L3Out's Node by its connected interfaces")
        mo_classes = ["sviIf", "l3RtdIf", "l3EncRtdIf"]
        for mo_class in mo_classes:
            managed_objs: List[Dict] = self.aci_rest.get_managed_objs_by_class(mo_class)
            for l3out in self.routes_to_l3outs[self.tenant][self.vrf]["L3Out"]:
                l3out_regex = fr".+/rtdOutDef-\[uni/tn-{self.tenant}/out-{l3out}\]"
                l3out_dn_pattern = re.compile(l3out_regex)
                for node in nodes:
                    node_regex = fr"topology/pod-[0-9]+/{node}/sys/ctx.+"
                    node_dn_pattern = re.compile(node_regex)
                    for managed_obj in managed_objs:
                        node_dn: str = managed_obj[mo_class]["attributes"]["dn"]
                        node_dn_match = node_dn_pattern.search(node_dn)
                        if node_dn_match:
                            l3out_dn: str = managed_obj[mo_class]["attributes"]["rtdOutDefDn"]
                            l3out_dn_match = l3out_dn_pattern.search(l3out_dn)
                            if l3out_dn_match:
                                intf: str = managed_obj[mo_class]["attributes"]["id"]
                                nodes[node]["Interfaces"][intf] = {"L3Out": l3out}

    def _query_vrf_routing_table(self, urib_class: str) -> List[Dict]:
        """
        Query a specific Tenant:VRF for its Unicast RIB

        Parameters:
            urib_class: Class name as string, uribv4Route or uribv6Route

        Returns:
            A list of dictionaries, each of which is for a route in the uRIB
        """

        child_query_level = "rsp-subtree=full"
        page_size = "page-size=100000&page=[0-4]"
        query_wcard = f'wcard({urib_class}.dn,"{self.tenant}:{self.vrf}/")'
        query_filter = f'query-target-filter={query_wcard}&{child_query_level}&{page_size}'
        logging.info(f"Downloading {urib_class}")
        managed_objs = self.aci_rest.get_managed_objs_by_class(urib_class, query_filter)
        return managed_objs

    def _load_l3outs_with_routes(self) -> None:
        """Merge routes of Nodes/Border-Leafs under their L3Outs"""

        def is_valid_intf(intf: str, intf_type: str):
            """Checks whether exit-interface is non-local and is routable"""

            return not (intf.startswith("lo") or intf == "null0" or intf_type in ("local", "am", "broadcast"))

        for urib in ["uribv4", "uribv6"]:
            nh_resolver = ModPyTricia.from_urib(urib)
            unknown_routes: DefaultDict[str, Set[str]] = defaultdict(set)
            urib_class, nh_class = f"{urib}Route", f"{urib}Nexthop"
            managed_objs = self._query_vrf_routing_table(urib_class)
            logging.info(f"Parsing {urib_class}")
            for managed_obj in managed_objs:
                node_dn: str = managed_obj[urib_class]["attributes"]["dn"]
                node = node_dn.split("/")[2]
                route: str = managed_obj[urib_class]["attributes"]["prefix"]
                for child in managed_obj[urib_class].get("children", []):
                    intf: str = child[nh_class]["attributes"]["if"]
                    intf_type: str = child[nh_class]["attributes"]["owner"]
                    next_hop: str = child[nh_class]["attributes"]["addr"]
                    tenant_to_vrf: str = child[nh_class]["attributes"]["vrf"]
                    if tenant_to_vrf == f"{self.tenant}:{self.vrf}" and is_valid_intf(intf, intf_type):
                        # If a route's next-hop is unknown (e.g. recursive), flag it as unknown for later resolution
                        if intf == "unspecified":
                            unknown_routes[route].add(next_hop)
                        else:
                            # Store routes' with resolvable next-hops
                            if not nh_resolver.has_key(route):
                                nh_resolver.insert(route, [(node, intf)])
                            else:
                                current_nhs: List[Tuple[str, str]] = nh_resolver.get(route)
                                current_nhs.append((node, intf))
                            l3out: str = self.nodes_to_l3outs[self.tenant][self.vrf]["Nodes"][node]["Interfaces"][intf]["L3Out"]
                            self.routes_to_l3outs[self.tenant][self.vrf]["L3Out"][l3out][urib].add(route)
            # Now that routes have been parsed, identify routes with unknown next-hops
            for route, next_hops in unknown_routes.items():
                for next_hop in next_hops:
                    current_nhs: List[Tuple[str, str]] = nh_resolver.get(next_hop)
                    for node, intf in current_nhs:
                        l3out: str = self.nodes_to_l3outs[self.tenant][self.vrf]["Nodes"][node]["Interfaces"][intf]["L3Out"]
                        self.routes_to_l3outs[self.tenant][self.vrf]["L3Out"][l3out][urib].add(route)


def add_user_args() -> ArgumentParser:
    """Sets CLI arguments and returns the parser object"""

    # Prepare Arguments
    parser = ArgumentParser()
    parser.add_argument("--username", help="Username", required=True)
    parser.add_argument("--device", help="APIC Hostname/IP", required=True)
    parser.add_argument("--tenant", help="Tenant", required=True)
    parser.add_argument("--vrf", help="VRF", required=True)
    parser.add_argument("--log", help="Enable info logging", required=False, action="store_true")
    return parser


def parse_user_args() -> Tuple[str, str, str, str, str, Optional[bool]]:
    """Parse loaded CLI arguments and return their values"""

    # Parse given args
    parser = add_user_args()
    parsed_args = parser.parse_args()

    # Extract values out of the args
    username: str = parsed_args.username
    password: str = getpass("Password: ")
    device: str = parsed_args.device
    tenant: str = parsed_args.tenant
    vrf: str = parsed_args.vrf
    logging_status: Optional[bool] = parsed_args.log

    return username, password, device, tenant, vrf, logging_status


def set_info_logging(logging_status: Optional[bool]) -> None:
    """Enable/Disable informational-level logging based on CLI argument"""

    if logging_status:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.disable()


def serialize_set_to_list(obj):
    """Serialize uRIB set to list and sort its content by their IP Network"""

    if isinstance(obj, (set, list)):
        return sorted(obj, key=ip_network)
    return obj


def main():
    """Main Function"""

    # Parse CLI args
    username, password, device, tenant, vrf, logging_status = parse_user_args()

    # Enable/Disable informational-level logging
    set_info_logging(logging_status)

    # Disable warnings while sending HTTPS requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Establish a connection to the APIC and return REST API handler
    with ACIConnect(username, password, device) as aci_rest:
        l3out_routing = L3OutRouting(tenant, vrf, aci_rest)
        routes_to_l3outs = l3out_routing.get_routes_via_l3outs()

    # Write results to disk as a JSON file
    output_file_name = f"{device}_{tenant}_{vrf}_routes.json"
    with open(output_file_name, "w", encoding="utf-8") as output_file:
        json.dump(routes_to_l3outs, output_file, default=serialize_set_to_list)


if __name__ == "__main__":
    main()
