"""ARM-backed, fail-closed verification of effective NIC egress controls."""
from __future__ import annotations

import ipaddress
import time
from urllib.parse import urlparse

API_NETWORK = "2025-05-01"
ARM_ORIGIN = "https://management.azure.com"


class EffectiveNetworkPolicyError(RuntimeError):
    """Effective Azure network state could not be proven safe."""


class AzureEffectiveNetworkPolicyVerifier:
    """Verify effective NSG rules and routes on the just-created NIC.

    required_outbound_flows is an explicit owner-reviewed list of
    {protocol: Tcp|Udp, port: int, destination: CIDR}. The flow must be
    explicitly allowed by every effective NSG (default allow rules do not
    count). The effective 0/0 route must point to the configured firewall.
    """

    def __init__(self, arm, expected_nsg_id, required_outbound_flows,
                 expected_firewall_ip, timeout_seconds=120, poll_interval=2,
                 clock=time.monotonic, sleep=time.sleep):
        self.arm = arm
        self.expected_nsg_id = self._resource_id(expected_nsg_id)
        self.expected_firewall_ip = str(ipaddress.ip_address(expected_firewall_ip))
        self.timeout_seconds = timeout_seconds
        self.poll_interval = poll_interval
        self.clock = clock
        self.sleep = sleep
        if not isinstance(required_outbound_flows, (list, tuple)) or not required_outbound_flows:
            raise ValueError("An explicit non-empty outbound allowlist is required")
        self.required_outbound_flows = tuple(self._flow(item) for item in required_outbound_flows)
        if timeout_seconds <= 0 or poll_interval < 0:
            raise ValueError("Invalid effective-network polling limits")

    @staticmethod
    def _resource_id(value):
        if not isinstance(value, str) or not value.startswith("/subscriptions/") or "/providers/Microsoft.Network/" not in value:
            raise ValueError("Expected a Microsoft.Network resource ID")
        return value.rstrip("/").lower()

    @staticmethod
    def _flow(value):
        if not isinstance(value, dict) or set(value) != {"protocol", "port", "destination"}:
            raise ValueError("Outbound flow must define protocol, port, and destination")
        protocol = value["protocol"]
        if protocol not in ("Tcp", "Udp"):
            raise ValueError("Outbound flow protocol must be Tcp or Udp")
        port = value["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Outbound flow port is invalid")
        network = ipaddress.ip_network(value["destination"], strict=False)
        return {"protocol": protocol, "port": port, "destination": network}

    def _arm_result(self, method, url, payload=None):
        request = getattr(self.arm, "request_with_metadata", None)
        if not callable(request):
            raise EffectiveNetworkPolicyError("ARM client does not expose response metadata; refusing unverified async operations")
        status, headers, body = request(method, url, payload)
        if status == 202:
            location = headers.get("Location") or headers.get("location")
            if not isinstance(location, str) or not location:
                raise EffectiveNetworkPolicyError("Azure returned 202 without an operation Location")
            parsed = urlparse(location)
            expected_scope = "/subscriptions/" + self.arm.subscription_id.lower() + "/"
            if (parsed.scheme != "https" or parsed.hostname != "management.azure.com"
                    or parsed.port not in (None, 443) or parsed.username or parsed.password
                    or parsed.fragment or expected_scope not in parsed.path.lower()
                    or "/providers/microsoft.network/" not in parsed.path.lower()):
                raise EffectiveNetworkPolicyError("Azure returned an untrusted async-operation URL")
            deadline = self.clock() + self.timeout_seconds
            while status == 202:
                if self.clock() >= deadline:
                    raise EffectiveNetworkPolicyError("Azure effective-network operation timed out")
                delay = min(self.poll_interval, max(0, int(headers.get("Retry-After", headers.get("retry-after", "1")))))
                if delay:
                    self.sleep(delay)
                status, headers, body = request("GET", location, None)
            if status != 200:
                raise EffectiveNetworkPolicyError("Azure effective-network operation did not complete successfully")
        if status != 200 or not isinstance(body, dict):
            raise EffectiveNetworkPolicyError("Azure effective-network response is missing or invalid")
        return body

    @staticmethod
    def _port_matches(rule, port):
        values = rule.get("destinationPortRanges")
        if values is None:
            values = [rule.get("destinationPortRange")]
        if not isinstance(values, list) or not values:
            return False
        for value in values:
            if value == "*":
                return True
            if not isinstance(value, str):
                continue
            try:
                if "-" in value:
                    low, high = (int(part) for part in value.split("-", 1))
                    if low <= port <= high:
                        return True
                elif int(value) == port:
                    return True
            except (ValueError, TypeError):
                continue
        return False

    @staticmethod
    def _address_matches(rule, destination):
        prefixes = rule.get("destinationAddressPrefixes")
        if prefixes is None:
            prefixes = [rule.get("destinationAddressPrefix")]
        expanded = rule.get("expandedDestinationAddressPrefix", [])
        if not isinstance(prefixes, list) or not isinstance(expanded, list):
            return False
        for prefix in prefixes + expanded:
            if not isinstance(prefix, str):
                continue
            try:
                if destination == ipaddress.ip_network(prefix, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _source_matches(rule, source):
        prefixes = rule.get("sourceAddressPrefixes")
        if prefixes is None:
            prefixes = [rule.get("sourceAddressPrefix")]
        expanded = rule.get("expandedSourceAddressPrefix", [])
        if not isinstance(prefixes, list) or not isinstance(expanded, list):
            return False
        for prefix in prefixes + expanded:
            if prefix == "*":
                return True
            if not isinstance(prefix, str):
                continue
            try:
                if source in ipaddress.ip_network(prefix, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _verify_nsg(self, body, nic_id, subnet_id, source_ips):
        groups = body.get("value")
        if not isinstance(groups, list) or not groups:
            raise EffectiveNetworkPolicyError("Effective NSG response contains no applied NSGs")
        rules_by_group = []
        matched_nsg = False
        for group in groups:
            if not isinstance(group, dict):
                raise EffectiveNetworkPolicyError("Effective NSG entry is malformed")
            association = group.get("association", {})
            associated_nic = association.get("networkInterface", {}).get("id")
            associated_subnet = association.get("subnet", {}).get("id")
            if not isinstance(associated_nic, str) or associated_nic.rstrip("/").lower() != nic_id.rstrip("/").lower():
                raise EffectiveNetworkPolicyError("Effective NSG response does not identify the expected NIC")
            if not isinstance(associated_subnet, str) or associated_subnet.rstrip("/").lower() != subnet_id.rstrip("/").lower():
                raise EffectiveNetworkPolicyError("Effective NSG response does not identify the expected subnet")
            nsg = group.get("networkSecurityGroup", {}).get("id")
            if nsg and nsg.rstrip("/").lower() == self.expected_nsg_id:
                matched_nsg = True
            rules = group.get("effectiveSecurityRules")
            if not isinstance(rules, list) or not rules:
                raise EffectiveNetworkPolicyError("Effective NSG rules are missing")
            rules_by_group.append(rules)
        if not matched_nsg:
            raise EffectiveNetworkPolicyError("Expected runner NSG is not associated with the NIC")
        for rules in rules_by_group:
            outbound = [r for r in rules if isinstance(r, dict) and r.get("direction") == "Outbound"]
            if not outbound:
                raise EffectiveNetworkPolicyError("Effective outbound NSG rules are missing")
            for flow in self.required_outbound_flows:
                for source_ip in source_ips:
                    candidates = []
                    for rule in outbound:
                        protocol = rule.get("protocol")
                        if protocol not in (flow["protocol"], "All"):
                            continue
                        if not self._port_matches(rule, flow["port"]):
                            continue
                        if not self._source_matches(rule, source_ip):
                            continue
                        if self._address_matches(rule, flow["destination"]):
                            priority = rule.get("priority")
                            if isinstance(priority, int) and not isinstance(priority, bool):
                                candidates.append((priority, rule.get("access")))
                    if not candidates:
                        raise EffectiveNetworkPolicyError("Required outbound flow has no effective rule for the NIC source IP")
                    priority, access = min(candidates, key=lambda item: item[0])
                    if access != "Allow" or priority >= 65000:
                        raise EffectiveNetworkPolicyError("Required outbound flow is denied or only covered by a default rule")

    def _verify_routes(self, body):
        routes = body.get("value")
        if not isinstance(routes, list) or not routes:
            raise EffectiveNetworkPolicyError("Effective route table is missing")
        defaults = []
        for route in routes:
            if not isinstance(route, dict):
                raise EffectiveNetworkPolicyError("Effective route entry is malformed")
            prefixes = route.get("addressPrefix")
            if isinstance(prefixes, str):
                prefixes = [prefixes]
            if not isinstance(prefixes, list) or any(not isinstance(item, str) for item in prefixes):
                continue
            if "0.0.0.0/0" in prefixes:
                defaults.append(route)
        if not defaults:
            raise EffectiveNetworkPolicyError("No effective IPv4 default route was returned")
        active_defaults = []
        for route in defaults:
            state = route.get("state")
            if state == "Invalid":
                continue
            if state not in ("Active", "active"):
                raise EffectiveNetworkPolicyError("Default route state is unknown")
            active_defaults.append(route)
            if route.get("nextHopType") != "VirtualAppliance":
                raise EffectiveNetworkPolicyError("Active default route bypasses the approved firewall")
            next_hops = route.get("nextHopIpAddress")
            if isinstance(next_hops, str):
                next_hops = [next_hops]
            if not isinstance(next_hops, list) or len(next_hops) != 1 or not isinstance(next_hops[0], str):
                raise EffectiveNetworkPolicyError("Default route must identify exactly one firewall next hop")
            try:
                if ipaddress.ip_address(next_hops[0]) != ipaddress.ip_address(self.expected_firewall_ip):
                    raise EffectiveNetworkPolicyError("Default route next hop does not match the approved firewall")
            except ValueError as exc:
                raise EffectiveNetworkPolicyError("Default route next hop is missing or invalid") from exc
        if not active_defaults:
            raise EffectiveNetworkPolicyError("No active effective IPv4 default route was returned")

    def _wait_for_nic(self, nic_name):
        url = self.arm.resource_url(
            "Microsoft.Network", "networkInterfaces", nic_name, API_NETWORK
        )
        deadline = self.clock() + self.timeout_seconds
        while self.clock() < deadline:
            data = self.arm.request("GET", url, allow_missing=True)
            if isinstance(data, dict):
                state = data.get("properties", {}).get("provisioningState")
                if state == "Succeeded":
                    configurations = data.get("properties", {}).get("ipConfigurations")
                    if not isinstance(configurations, list) or not configurations:
                        raise EffectiveNetworkPolicyError("Azure NIC has no effective private IP configuration")
                    addresses = []
                    primary_count = 0
                    for configuration in configurations:
                        properties = configuration.get("properties", {}) if isinstance(configuration, dict) else {}
                        address = properties.get("privateIPAddress")
                        try:
                            addresses.append(ipaddress.ip_address(address))
                        except ValueError as exc:
                            raise EffectiveNetworkPolicyError("Azure NIC private IP is missing or invalid") from exc
                        if properties.get("primary") is True:
                            primary_count += 1
                    if primary_count != 1:
                        raise EffectiveNetworkPolicyError("Azure NIC must have exactly one primary IP configuration")
                    return tuple(addresses)
                if state in ("Failed", "Canceled", "Deleting", "Deleted"):
                    raise EffectiveNetworkPolicyError("Azure NIC provisioning did not succeed")
            self.sleep(self.poll_interval or 1)
        raise EffectiveNetworkPolicyError("Azure NIC did not reach Succeeded before egress verification")

    def verify_nic(self, nic_id, expected_nsg_id, subnet_id):
        try:
            if self._resource_id(expected_nsg_id) != self.expected_nsg_id:
                raise EffectiveNetworkPolicyError("Verifier NSG scope does not match the provisioner")
            nic = self._resource_id(nic_id)
            if f"/subscriptions/{self.arm.subscription_id.lower()}/" not in nic:
                raise EffectiveNetworkPolicyError("NIC is outside the configured subscription")
            nic_name = nic.rsplit("/", 1)[-1]
            source_ips = self._wait_for_nic(nic_name)
            nic_url = self.arm.resource_url(
                "Microsoft.Network", "networkInterfaces",
                nic_name, API_NETWORK
            ).split("?", 1)[0]
            nsg_url = nic_url + "/effectiveNetworkSecurityGroups?api-version=" + API_NETWORK
            route_url = nic_url + "/effectiveRouteTable?api-version=" + API_NETWORK
            nsg = self._arm_result("POST", nsg_url, {})
            routes = self._arm_result("POST", route_url, {})
            self._verify_nsg(nsg, nic_id, subnet_id, source_ips)
            self._verify_routes(routes)
            return True
        except EffectiveNetworkPolicyError:
            raise
        except Exception as exc:
            raise EffectiveNetworkPolicyError("Effective Azure network state could not be verified") from exc
