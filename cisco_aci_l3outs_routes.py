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
    - `--log` Enable info logging (optional)

User Input:
    - Password

Script Output:
    - JSON file with APIC:Tenant:VRF:L3Out:RIB details

Preset Values:
    - Timeout for HTTP login/logout requests set to 10 seconds
    - Timeout for downloading a Class's Managed Objects set to 60 seconds
"""

import json
import logging
import re
import sys
from argparse import ArgumentParser
from getpass import getpass
from ipaddress import _BaseNetwork, ip_network
from itertools import islice
from typing import Generator, Iterator, List, Optional, Tuple

import requests
import urllib3


def prefix_bits(network: str) -> Iterator[str]:
    """
    Returns an iterator for an IP network's prefix bits.

    >>> "".join(prefix_bits("192.168.1.0/24"))
        '110000001010100000000001'
    >>> "".join(prefix_bits("2a01:db8:acad:1::/64"))
        '0010101000000001000011011011100010101100101011010000000000000001'
    """

    if not isinstance(network, _BaseNetwork):
        network = ip_network(network, strict=False)
    if network.version == 4:
        binary_bits = f"{int(network.network_address):032b}"
    else:
        binary_bits = f"{int(network.network_address):0128b}"
    return islice(binary_bits, network.prefixlen)


class Route:
    """
    Instatiate Route object that stores well-known routing attributes.
    """

    def __init__(
        self,
        prefix: str,
        *,
        next_hop: Optional[str] = None,
        interface: Optional[str] = None,
        node: Optional[str] = None,
    ) -> None:
        """Constructs a Route object with the provided attributes."""

        self.prefix = prefix
        self.next_hop = next_hop
        self.interface = interface
        self.node = node

    def has_all_attrs(self, **kwargs) -> bool:
        """
        Returns True if all of the provided kwargs are attributes of the Route
        object, False otherwise.
        """

        return all(getattr(self, attr) == val for attr, val in kwargs.items())


class RoutingTable:
    """
    Container for objects of the Route's class.

    Route objects can be accessed by traversing an IP prefix tree.

    An IP prefix will have its binary digits (bits) stored as trie-nodes where
    the ending digit points to a Route object.
    """

    def __init__(self, urib_version: str) -> None:
        """Initializes an empty Prefix-Tree (a root node)."""

        self.urib_version = urib_version
        self._root = {}

    def __iter__(self) -> Generator[Route, None, None]:
        """Iterator that yields each installed Route object."""

        yield from self._traverse(self._root)

    def _traverse(self, root: dict, **kwargs) -> Generator[Route, None, None]:
        """
        A generator function that recursively traverses a given tree to yield
        each installed Route object downstream.
        """

        nodes = list(root.items())
        while nodes:
            node, children = nodes.pop()
            if node == "*":
                routes: List[Route] = children
                for route in routes:
                    if route.has_all_attrs(**kwargs):
                        yield route
            else:
                children: dict
                nodes.extend(children.items())

    def add(self, prefix: str, **kwargs) -> None:
        """Extends the prefix tree by new IP prefix and/or a Route object."""

        route = Route(prefix, **kwargs)
        node = self._root
        for bit in prefix_bits(prefix):
            if bit not in node:
                node[bit] = {}
            node = node[bit]
        routes: list = node.get("*", [])
        routes.append(route)
        node["*"] = routes

    def get(self, prefix: str, **kwargs) -> List[Route]:
        """
        Returns the longest match Route objects for a given prefix/address.
        """

        node = self._root
        routes: List[Route] = node.get("*", [])
        for bit in prefix_bits(prefix):
            if bit not in node:
                break
            node: dict = node[bit]
            routes = node.get("*", routes)
        return [route for route in routes if route.has_all_attrs(**kwargs)]


class ACIConnect:
    """
    A REST API connection-handler for Cisco APIC that manages HTTPS session
    establishment and termination.

    Provides two REST API GET methods
        1) GET Managed Objs by their Class
        2) GET specific Managed Object by its DN
    """

    def __init__(self, username: str, password: str, device: str) -> None:
        """Constructor"""

        self.device = device
        self.username = username
        self.password = password
        self.apic_cookies = {}

    def __enter__(self):
        """Connect to APIC"""

        self.apic_login()
        return self

    def __exit__(self, *args) -> None:
        """Graceful logout from APIC"""

        if self.apic_cookies:
            self.apic_logout()

    @property
    def json_creds(self) -> str:
        """Prepare credentials to be used as JSON object"""

        creds = {"name": self.username, "pwd": self.password}
        return json.dumps({"aaaUser": {"attributes": creds}})

    def apic_login(self) -> None:
        """POST login request and update apic_cookies instance variable"""

        login_uri = f"https://{self.device}/api/aaaLogin.json"

        logging.info("Connecting to %s", self.device)

        try:
            resp = requests.post(login_uri, data=self.json_creds, verify=False, timeout=10)
        except requests.exceptions.ConnectionError:
            logging.error("APIC is unreachable by FQDN/IP")
            sys.exit(1)

        if resp.status_code in (400, 404):
            logging.error("Bad HTTP POST login request, wrong hostname or FQDN/IP")
            sys.exit(1)
        elif resp.status_code == 401:
            logging.error("Wrong username or password provided")
            sys.exit(1)
        else:
            content: dict = resp.json()
            cookies: str = content["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.apic_cookies.update({"APIC-Cookie": cookies})

    def apic_logout(self) -> None:
        """POST logout request"""

        logout_uri = f"https://{self.device}/api/aaaLogout.json"
        requests.post(logout_uri, cookies=self.apic_cookies, verify=False, timeout=10)

    def get_managed_objs_by_class(
        self, mo_class: str, query_filter: Optional[str] = None
    ) -> List[dict]:
        """Returns a list of managed objects dictionaries of a given MO Class"""

        logging.info("GET Managed Objs of Class: %s", mo_class)
        uri = f"https://{self.device}/api/class/{mo_class}.json"
        if query_filter:
            uri += f"?{query_filter}"
        resp = requests.get(uri, cookies=self.apic_cookies, verify=False, timeout=60)
        content: dict = resp.json()
        managed_objs: List[dict] = content["imdata"]
        return managed_objs

    def get_managed_objs_by_dn(self, dn: str, query_filter: Optional[str] = None) -> List[dict]:
        """Returns a list of Managed Objects dictionaries of a given DN"""

        uri = f"https://{self.device}/api/mo/{dn}.json"
        if query_filter:
            uri += f"?{query_filter}"
        resp = requests.get(uri, cookies=self.apic_cookies, verify=False, timeout=60)
        content: dict = resp.json()
        managed_objs: List[dict] = content["imdata"]
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
        self._routes_to_l3outs = {tenant: {vrf: {"L3Out": {}}}}
        self._nodes_to_l3outs = {tenant: {vrf: {"Nodes": {}}}}
        self._vrf_in_tenant_check()

    def _vrf_in_tenant_check(self) -> None:
        """Checks whether the VRF is associated with the Tenant or not"""

        tenant_dn = f"uni/tn-{self.tenant}"
        vrf_in_tenant_dn = f"uni/tn-{self.tenant}/ctx-{self.vrf}"
        if not self.aci_rest.get_managed_objs_by_dn(tenant_dn):
            logging.error("Provided tenant doesn't exist")
            sys.exit(1)
        if not self.aci_rest.get_managed_objs_by_dn(vrf_in_tenant_dn):
            logging.error("Provided VRF doesn't exist")
            sys.exit(1)

    def get_routes_via_l3outs(self) -> dict:
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
        self._parse_unicast_ribs()
        return self._routes_to_l3outs

    def _load_l3outs_in_vrf(self) -> None:
        """Updates the VRF by its L3Outs and initialize empty uRIB IPv4|6 tables for each L3Out"""

        logging.info("Loading L3Out names")
        managed_objs: List[dict] = self.aci_rest.get_managed_objs_by_class("l3extRsEctx")
        l3out_dn_pattern = re.compile(rf"uni/tn-{self.tenant}/out-(.+)/rsectx")
        l3outs = self._routes_to_l3outs[self.tenant][self.vrf]["L3Out"]
        for managed_obj in managed_objs:
            attributes = managed_obj["l3extRsEctx"]["attributes"]
            l3out_associated_vrf: str = attributes["tnFvCtxName"]
            if self.vrf == l3out_associated_vrf:
                l3out_dn: str = attributes["dn"]
                l3out_match = l3out_dn_pattern.search(l3out_dn)
                if l3out_match:
                    l3out = l3out_match.group(1)
                    l3outs[l3out] = {"uribv4": set(), "uribv6": set()}
        if not l3outs:
            logging.error("VRF has no L3Outs associated with it")
            sys.exit(1)

    def _load_nodes_of_l3outs(self) -> None:
        """Stores Nodes used in L3Outs and initialize empty Interfaces dictionary"""

        logging.info("Loading Nodes-IDs associated with the VRF's L3Outs")
        managed_objs: List[dict] = self.aci_rest.get_managed_objs_by_class("l3extRsNodeL3OutAtt")
        nodes = self._nodes_to_l3outs[self.tenant][self.vrf]["Nodes"]
        for l3out in self._routes_to_l3outs[self.tenant][self.vrf]["L3Out"]:
            regex = rf"uni/tn-{self.tenant}/out-{l3out}/lnodep-.+/rsnodeL3OutAtt-\[topology/pod-[0-9]+/(.+)\]"
            node_dn_pattern = re.compile(regex)
            for managed_obj in managed_objs:
                node_dn: str = managed_obj["l3extRsNodeL3OutAtt"]["attributes"]["dn"]
                node_dn_match = node_dn_pattern.search(node_dn)
                if node_dn_match:
                    node = node_dn_match.group(1)
                    nodes[node] = {"Interfaces": {}}
        if not nodes:
            logging.error("None of the L3Outs have associated Node(s)")
            sys.exit(1)

    def _load_nodes_by_their_connected_intfs(self) -> None:
        """
        Maps each Node interface to its associated L3Out

        A Node interface can be:
            - Routed Interface
            - Routed Sub-Interface
            - SVI
        """

        nodes = self._nodes_to_l3outs[self.tenant][self.vrf]["Nodes"]
        logging.info("Loading each L3Out's Node by its connected interfaces")
        mo_classes = ["sviIf", "l3RtdIf", "l3EncRtdIf"]
        for mo_class in mo_classes:
            managed_objs: List[dict] = self.aci_rest.get_managed_objs_by_class(mo_class)
            for l3out in self._routes_to_l3outs[self.tenant][self.vrf]["L3Out"]:
                l3out_regex = rf".+/rtdOutDef-\[uni/tn-{self.tenant}/out-{l3out}\]"
                l3out_dn_pattern = re.compile(l3out_regex)
                for node in nodes:
                    node_regex = rf"topology/pod-[0-9]+/{node}/sys/ctx.+"
                    node_dn_pattern = re.compile(node_regex)
                    for managed_obj in managed_objs:
                        attributes = managed_obj[mo_class]["attributes"]
                        node_dn: str = attributes["dn"]
                        node_dn_match = node_dn_pattern.search(node_dn)
                        if node_dn_match:
                            l3out_dn: str = attributes["rtdOutDefDn"]
                            l3out_dn_match = l3out_dn_pattern.search(l3out_dn)
                            if l3out_dn_match:
                                intf: str = attributes["id"]
                                nodes[node]["Interfaces"][intf] = {"L3Out": l3out}

    def _query_vrf_routing_table(self, urib_class: str) -> List[dict]:
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
        query_filter = f"query-target-filter={query_wcard}&{child_query_level}&{page_size}"
        logging.info("Downloading %s", urib_class)
        managed_objs = self.aci_rest.get_managed_objs_by_class(urib_class, query_filter)
        return managed_objs

    def _load_l3outs_with_routes(self, rib: RoutingTable):
        l3outs = self._routes_to_l3outs[self.tenant][self.vrf]["L3Out"]
        nodes = self._nodes_to_l3outs[self.tenant][self.vrf]["Nodes"]
        for route in rib:
            node, interface = route.node, route.interface
            if interface == "unspecified":
                next_hops = rib.get(route.next_hop)
                for next_hop in next_hops:
                    node, interface = next_hop.node, next_hop.interface
                    l3out = nodes[node]["Interfaces"][interface]["L3Out"]
                    l3outs[l3out]["RIB"][rib.urib_version].add(route.prefix)
            else:
                l3out = nodes[node]["Interfaces"][interface]["L3Out"]
                l3outs[l3out]["RIB"][rib.urib_version].add(route.prefix)

    def _parse_unicast_ribs(self) -> None:
        """Merge routes of Nodes/Border-Leafs under their L3Outs"""

        for urib_version in ["uribv4", "uribv6"]:
            rib = RoutingTable(urib_version=urib_version)
            urib_class = f"{urib_version}Route"
            nh_class = f"{urib_version}Nexthop"
            managed_objs = self._query_vrf_routing_table(urib_class)
            logging.info("Parsing %s table", urib_version)
            for managed_obj in managed_objs:
                attributes = managed_obj[urib_class]["attributes"]
                node: str = attributes["dn"].split("/")[2]
                prefix: str = attributes["prefix"]
                for child in managed_obj[urib_class].get("children", []):
                    child_attributes = child[nh_class]["attributes"]
                    interface: str = child_attributes["if"]
                    scope: str = child_attributes["owner"]
                    next_hop: str = child_attributes["addr"]
                    tenant_to_vrf: str = child_attributes["vrf"]
                    if (
                        tenant_to_vrf == f"{self.tenant}:{self.vrf}"
                        and scope not in ("local", "am", "broadcast")
                        and not interface.startswith("lo")
                        and interface != "null0"
                    ):
                        rib.add(prefix, next_hop=next_hop, interface=interface, node=node)
            self._load_l3outs_with_routes(self, rib)


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


def set_logging_level(info_logging: Optional[bool]) -> None:
    """Set minimum logging level"""

    if info_logging:
        level = logging.INFO
    else:
        level = logging.ERROR
    logging.basicConfig(level=level)


def serialize_set_to_list(obj):
    """Serialize uRIB set to list and sort its content by their IP Network"""

    if isinstance(obj, (set, list)):
        return sorted(obj, key=ip_network)
    return obj


def main():
    """Main Function"""

    # Parse CLI args
    username, password, device, tenant, vrf, info_logging = parse_user_args()

    # Set minimum logging level
    set_logging_level(info_logging)

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
