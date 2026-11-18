"""Local host inventory and explicitly scoped TCP network discovery."""
from __future__ import annotations

import ipaddress
import platform
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import psutil

COMMON_PORTS = {
    22: "SSH", 53: "DNS", 80: "HTTP", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "JetDirect",
}
CONNECT_TIMEOUT = 0.22
MAX_WORKERS = 64


def local_networks() -> list[dict]:
    """Return active, non-loopback private IPv4 networks on this machine."""
    networks: list[dict] = []
    for name, addresses in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if stats is not None and not stats.isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.address or not address.netmask:
                continue
            try:
                interface = ipaddress.ip_interface(f"{address.address}/{address.netmask}")
            except ValueError:
                continue
            network = interface.network
            if interface.ip.is_loopback or interface.ip.is_link_local or not network.is_private:
                continue
            networks.append({
                "interface": name,
                "address": str(interface.ip),
                "network": str(network),
                "prefix_length": network.prefixlen,
            })
    return networks


def validate_local_network(value: str) -> ipaddress.IPv4Network:
    """Only allow /24-or-smaller IPv4 ranges attached to a local interface."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 CIDR network.") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 local networks are supported.")
    if not network.is_private or network.prefixlen < 24:
        raise ValueError("Only private IPv4 ranges of /24 or smaller may be scanned.")
    if not any(network.subnet_of(ipaddress.ip_network(item["network"])) for item in local_networks()):
        raise ValueError("The selected range is not attached to an active local interface.")
    return network


def system_inventory() -> dict:
    """Collect a read-only inventory; process command lines and file contents are excluded."""
    memory = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage(str(Path.home().anchor or "/"))
    except OSError:
        disk = None

    processes: list[dict] = []
    for process in psutil.process_iter(["pid", "name", "username", "status"]):
        try:
            info = process.info
            processes.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "unknown",
                "user": info.get("username"),
                "status": info.get("status"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    processes.sort(key=lambda item: (item["name"].lower(), item["pid"] or 0))

    listeners: list[dict] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        connections = []
    for connection in connections:
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        try:
            process_name = psutil.Process(connection.pid).name() if connection.pid else None
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = None
        listeners.append({
            "address": connection.laddr.ip,
            "port": connection.laddr.port,
            "process": process_name,
            "pid": connection.pid,
        })
    listeners.sort(key=lambda item: (item["port"], item["address"]))

    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET:
                interfaces.append({"name": name, "address": address.address, "netmask": address.netmask})

    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "operating_system": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Not reported by operating system",
        "cpu_cores": psutil.cpu_count(logical=False),
        "logical_processors": psutil.cpu_count(logical=True),
        "memory": {"total_bytes": memory.total, "available_bytes": memory.available, "used_percent": memory.percent},
        "disk": None if disk is None else {"total_bytes": disk.total, "free_bytes": disk.free, "used_percent": disk.percent},
        "interfaces": interfaces,
        "local_networks": local_networks(),
        "process_count": len(processes),
        "processes": processes[:100],
        "processes_truncated": len(processes) > 100,
        "listening_services": listeners,
        "listening_services_note": "Visibility depends on the permissions used to run SENTINEL.",
    }


def _probe_host(address: str) -> dict | None:
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.create_connection((address, port), timeout=CONNECT_TIMEOUT):
                open_ports.append({"port": port, "service": service})
        except (OSError, TimeoutError):
            continue
    if not open_ports:
        return None
    return {"address": address, "open_services": open_ports}


def network_discovery(cidr: str) -> dict:
    """Probe a validated local /24 (or narrower) using a fixed low-impact TCP port list."""
    network = validate_local_network(cidr)
    hosts = [str(address) for address in network.hosts()]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(_probe_host, hosts))
    discovered = [item for item in results if item is not None]
    return {
        "network": str(network),
        "method": "TCP connect checks against a fixed common-service port list",
        "ports_checked": [{"port": port, "service": service} for port, service in COMMON_PORTS.items()],
        "addresses_checked": len(hosts),
        "responsive_hosts": len(discovered),
        "hosts": discovered,
        "limitations": "Hosts with no responding checked TCP ports are not reported. This is discovery, not a vulnerability assessment.",
    }
