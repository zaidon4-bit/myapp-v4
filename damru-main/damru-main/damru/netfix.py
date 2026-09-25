"""WSL/Redroid network repair helpers.

Host-network Redroid runs Android netd in the WSL network namespace. Android
can leave policy routing, iptables, and forwarding in a state that is valid for
Android internals but broken for WSL/Docker/Chrome DNS. These helpers are
idempotent and intentionally narrow to Damru's WSL repair path.
"""
from __future__ import annotations


def wsl_runtime_network_repair_lines() -> list[str]:
    """Return shell lines that restore WSL routing, DNS, and Docker NAT."""
    android_chain_regex = "(^-A (oem_|fw_|bw_|st_|tetherctrl_)|^-N (oem_|fw_|bw_|st_|tetherctrl_))"
    return [
        "set +e",
        "is_wsl=0",
        "[ -n \"${DAMRU_FORCE_WSL_REPAIR:-}\" ] && is_wsl=1",
        "grep -qi microsoft /proc/version 2>/dev/null && is_wsl=1",
        "[ -n \"${WSL_INTEROP:-}\" ] && is_wsl=1",
        "[ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && is_wsl=1",
        "[ -d /run/WSL ] && is_wsl=1",
        "[ -d /mnt/c ] && is_wsl=1",
        "if [ \"$is_wsl\" = 1 ]; then",
        "  while ip rule show | grep -q '^9999:'; do ip rule del pref 9999 2>/dev/null || break; done",
        "  ip rule add pref 9999 lookup main 2>/dev/null || true",
        "  while ip rule show | grep -q '^31999:'; do ip rule del pref 31999 2>/dev/null || break; done",
        "  ip rule add pref 31999 lookup main 2>/dev/null || true",
        "  mkdir -p /home/damru/state 2>/dev/null || true",
        "  wsl_cidr=$(ip -4 -o addr show eth0 | awk '{print $4; exit}')",
        "  if [ -z \"$wsl_cidr\" ] && [ -r /home/damru/state/wsl-net.env ]; then",
        "    . /home/damru/state/wsl-net.env 2>/dev/null || true",
        "    wsl_cidr=${WSL_CIDR:-}",
        "    [ -n \"$wsl_cidr\" ] && ip addr replace \"$wsl_cidr\" dev eth0 2>/dev/null || true",
        "  fi",
        "  wsl_ip=${wsl_cidr%/*}",
        "  wsl_prefix=${wsl_cidr#*/}",
        "  if [ -n \"$wsl_ip\" ]; then",
        "    o1=${wsl_ip%%.*}; rest=${wsl_ip#*.}",
        "    o2=${rest%%.*}; rest=${rest#*.}",
        "    o3=${rest%%.*}",
        "    gw=$o1.$o2.$((o3 / 16 * 16)).1",
        "    [ -n \"$wsl_prefix\" ] && printf 'WSL_CIDR=%s\\nWSL_GW=%s\\n' \"$wsl_ip/$wsl_prefix\" \"$gw\" > /home/damru/state/wsl-net.env 2>/dev/null || true",
        "    [ -n \"$gw\" ] && ip route replace default via \"$gw\" dev eth0 onlink table main 2>/dev/null || true",
        "  fi",
        "fi",
        "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true",
        "if [ \"$is_wsl\" = 1 ] && command -v python3 >/dev/null 2>&1; then",
        "  mkdir -p /home/damru/bin /home/damru/logs 2>/dev/null || true",
        "  cat > /home/damru/bin/damru-dns-tcp-proxy.py <<'PY'",
        "#!/usr/bin/env python3",
        "import socket, struct, threading",
        "UPSTREAMS = [('1.1.1.1', 53), ('8.8.8.8', 53), ('10.255.255.254', 53)]",
        "def forward_tcp(query):",
        "    packet = struct.pack('!H', len(query)) + query",
        "    last = None",
        "    for upstream in UPSTREAMS:",
        "        try:",
        "            with socket.create_connection(upstream, timeout=4) as s:",
        "                s.settimeout(4)",
        "                s.sendall(packet)",
        "                hdr = s.recv(2)",
        "                if len(hdr) != 2:",
        "                    continue",
        "                size = struct.unpack('!H', hdr)[0]",
        "                data = b''",
        "                while len(data) < size:",
        "                    chunk = s.recv(size - len(data))",
        "                    if not chunk:",
        "                        break",
        "                    data += chunk",
        "                if len(data) == size:",
        "                    return data",
        "        except Exception as exc:",
        "            last = exc",
        "    raise RuntimeError(str(last) if last else 'no upstream DNS response')",
        "def serve():",
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
        "    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
        "    sock.bind(('127.0.0.1', 53))",
        "    while True:",
        "        query, addr = sock.recvfrom(4096)",
        "        threading.Thread(target=handle, args=(sock, query, addr), daemon=True).start()",
        "def handle(sock, query, addr):",
        "    try:",
        "        sock.sendto(forward_tcp(query), addr)",
        "    except Exception:",
        "        if len(query) >= 12:",
        "            flags = b'\\x81\\x82'",
        "            sock.sendto(query[:2] + flags + query[4:6] + b'\\x00\\x00\\x00\\x00\\x00\\x00' + query[12:], addr)",
        "if __name__ == '__main__':",
        "    serve()",
        "PY",
        "  chmod 755 /home/damru/bin/damru-dns-tcp-proxy.py 2>/dev/null || true",
        "  if ! ss -lun 2>/dev/null | grep -q '127\\.0\\.0\\.1:53'; then",
        "    nohup python3 /home/damru/bin/damru-dns-tcp-proxy.py >/home/damru/logs/dns-tcp-proxy.log 2>&1 &",
        "    sleep 0.4",
        "  fi",
        "fi",
        f"if iptables -S 2>/dev/null | grep -Eq '{android_chain_regex}' || iptables -t nat -S 2>/dev/null | grep -Eq '{android_chain_regex}'; then",
        "  iptables -F 2>/dev/null || true",
        "  iptables -t nat -F 2>/dev/null || true",
        "  iptables -t mangle -F 2>/dev/null || true",
        "  iptables -P FORWARD ACCEPT 2>/dev/null || true",
        "fi",
        "if docker info >/dev/null 2>/dev/null && docker network inspect bridge >/dev/null 2>/dev/null; then",
        "  docker_subnet=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)",
        "  docker_if=$(docker network inspect bridge --format '{{.Options.com.docker.network.bridge.name}}' 2>/dev/null)",
        "  [ -n \"$docker_if\" ] || docker_if=docker0",
        "  [ \"$docker_if\" != \"<no value>\" ] || docker_if=docker0",
        "  if [ -n \"$docker_subnet\" ] && ip link show \"$docker_if\" >/dev/null 2>&1; then",
        "    iptables -C FORWARD -i \"$docker_if\" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i \"$docker_if\" -j ACCEPT 2>/dev/null || true",
        "    iptables -C FORWARD -o \"$docker_if\" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o \"$docker_if\" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true",
        "    iptables -t nat -C POSTROUTING -s \"$docker_subnet\" ! -o \"$docker_if\" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s \"$docker_subnet\" ! -o \"$docker_if\" -j MASQUERADE 2>/dev/null || true",
        "  fi",
        "fi",
        "if [ \"$is_wsl\" = 1 ]; then",
        "  if ss -lun 2>/dev/null | grep -q '127\\.0\\.0\\.1:53' && ! grep -q '^nameserver 127\\.0\\.0\\.1' /etc/resolv.conf 2>/dev/null; then",
        "    cp /etc/resolv.conf /etc/resolv.conf.damru.bak 2>/dev/null || true",
        "    printf 'nameserver 127.0.0.1\\n' > /etc/resolv.conf",
        "  fi",
        "fi",
    ]


def wsl_runtime_network_repair_script() -> str:
    return "\n".join(wsl_runtime_network_repair_lines())


def android_dns_repair_command(*, use_wsl_dns_proxy: bool = False) -> str:
    """Return an Android shell command that restores resolver props.

    WSL host-network Redroid shares the WSL network namespace, so Android can
    use Damru's local UDP-to-TCP DNS proxy on 127.0.0.1. Native Linux/Docker
    bridge workers cannot use that address because it points inside Android.
    """
    if use_wsl_dns_proxy:
        return "setprop net.dns1 127.0.0.1; setprop net.dns2 1.1.1.1; true"
    return "setprop net.dns1 1.1.1.1; setprop net.dns2 8.8.8.8; true"
