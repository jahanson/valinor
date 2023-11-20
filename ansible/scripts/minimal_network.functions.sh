#!/usr/bin/env bash
# https://github.com/hetzneronline/installimage/blob/master/network_config.functions.sh

#
# network config functions
#
# (c) 2017-2021, Hetzner Online GmbH
#

# list network interfaces
network_interfaces() {
  for file in /sys/class/net/*; do
    echo "${file##*/}"
  done
}

# check whether network interface is virtual
# $1 <network_interface>
network_interface_is_virtual() {
  local network_interface="$1"
  [[ -d "/sys/devices/virtual/net/$network_interface" ]]
}

# list physical network interfaces
physical_network_interfaces() {
  while read network_interface; do
    network_interface_is_virtual "$network_interface" && continue
    echo "$network_interface"
  done < <(network_interfaces)
}

# conv int to ipv4 addr
# $1 <int>
int_to_ipv4_addr() {
  local int="$1"
  echo "$(((int >> 24) & 0xff)).$(((int >> 16) & 0xff)).$(((int >> 8) & 0xff)).$((int & 0xff))/32"
}

# check whether network contains ipv4 addr
# $1 <network>
# $2 <ipv4_addr>
network_contains_ipv4_addr() {
  local network="$1"
  local ipv4_addr="$2"
  ipv4_addr="$(ip_addr_without_suffix "$ipv4_addr")/$(ip_addr_suffix "$network")"
  [[ "$(ipv4_addr_network "$ipv4_addr")" == "$network" ]]
}

# check whether ipv4 addr is private
# $1 <ipv4_addr>
ipv4_addr_is_private() {
  local ipv4_addr="$1"
  network_contains_ipv4_addr 10.0.0.0/8 "$ipv4_addr" ||
  network_contains_ipv4_addr 172.16.0.0/12 "$ipv4_addr" ||
  network_contains_ipv4_addr 192.168.0.0/16 "$ipv4_addr"
}

# conv ipv4 addr to int
# $1 <ipv4_addr>
ipv4_addr_to_int() {
  local ipv4_addr="$1"
  local ipv4_addr_without_suffix="$(ip_addr_without_suffix "$ipv4_addr")"
  { IFS=. read a b c d; } <<< "$ipv4_addr_without_suffix"
  echo "$(((((((a << 8) | b) << 8) | c) << 8) | d))"
}

# calc ipv4 addr netmask
# $1 <ipv4_addr>
ipv4_addr_netmask() {
  local ipv4_addr="$1"
  local ipv4_addr_suffix="$(ip_addr_suffix "$ipv4_addr")"
  ip_addr_without_suffix "$(int_to_ipv4_addr "$((0xffffffff << (32 - ipv4_addr_suffix)))")"
}

# get ip addr suffix
# $1 <ip_addr>
ip_addr_suffix() {
  local ip_addr="$1"
  if [[ "$ip_addr" =~ / ]]; then
    echo "${ip_addr##*/}"
  # assume /32 unless $ip_addr contains /
  else
    echo 32
  fi
}

# get ip addr without suffix
# $1 <ip_addr>
ip_addr_without_suffix() {
  local ip_addr="$1"
  echo "${ip_addr%%/*}"
}

# calc ipv4 addr network
# $1 <ipv4_addr>
ipv4_addr_network() {
  local ipv4_addr="$1"
  local ipv4_addr_suffix="$(ip_addr_suffix "$ipv4_addr")"
  local int="$(ipv4_addr_to_int "$ipv4_addr")"
  local network_without_suffix="$(ip_addr_without_suffix "$(int_to_ipv4_addr "$((int & (0xffffffff << (32 - ipv4_addr_suffix))))")")"
  echo "$network_without_suffix/$ipv4_addr_suffix"
}

# check whether network contains ipv4 addr
# $1 <network>
# $2 <ipv4_addr>
network_contains_ipv4_addr() {
  local network="$1"
  local ipv4_addr="$2"
  ipv4_addr="$(ip_addr_without_suffix "$ipv4_addr")/$(ip_addr_suffix "$network")"
  [[ "$(ipv4_addr_network "$ipv4_addr")" == "$network" ]]
}

# check whether ipv4 addr is a shared addr (rfc6598)
# $1 <ipv4_addr>
ipv4_addr_is_shared_addr() {
  local ipv4_addr="$1"
  network_contains_ipv4_addr 100.64.0.0/10 "$ipv4_addr"
}

# check if ipv4 addr is reserved for future use
ipv4_addr_is_reserved_for_future_use() {
  local ipv4_addr="$1"
  network_contains_ipv4_addr 240.0.0.0/4 "$ipv4_addr"
}

# get network interface ipv4 addrs
# $1 <network_interface>
network_interface_ipv4_addrs() {
  local network_interface="$1"
  while read line; do
    [[ "$line" =~ ^\ *inet\ ([^\ ]+) ]] || continue
    local ipv4_addr="${BASH_REMATCH[1]}"
    # ignore shared addrs
    ipv4_addr_is_shared_addr "$ipv4_addr" && continue
    # ignore addrs reserved for future use
    ipv4_addr_is_reserved_for_future_use "$ipv4_addr" && continue
    echo "$ipv4_addr"
  done < <(ip -4 a s "$network_interface")
}

# get network interface ipv4 gateway
# $1 <network_interface>
network_interface_ipv4_gateway() {
  local network_interface="$1"
  [[ "$(ip -4 r l 0/0 dev "$network_interface")" =~ ^default\ via\ ([^\ $'\n']+) ]] && echo "${BASH_REMATCH[1]}"
}

# get network interface ipv6 gateway
# $1 <network_interface>
network_interface_ipv6_gateway() {
  local network_interface="$1"
  [[ "$(ip -6 r l ::/0 dev "$network_interface")" =~ ^default\ via\ ([^\ $'\n']+) ]] && echo "${BASH_REMATCH[1]}"
}

# check whether ipv6 addr is a link local unicast addr
# $1 <ipv6_addr>
ipv6_addr_is_link_local_unicast_addr() {
  local ipv6_addr="$1"
  [[ "$ipv6_addr" =~ ^fe80: ]]
}

# get network interface ipv6 addrs
# $1 <network_interface>
network_interface_ipv6_addrs() {
  # "hide" v6 if IPV4_ONLY set
  ((IPV4_ONLY == 1)) && return

  local network_interface="$1"
  while read line; do
    [[ "$line" =~ ^\ *inet6\ ([^\ ]+) ]] || continue
    local ipv6_addr="${BASH_REMATCH[1]}"
    # ignore link local unicast addrs
    ipv6_addr_is_link_local_unicast_addr "$ipv6_addr" && continue
    echo "$ipv6_addr"
  done < <(ip -6 a s "$network_interface")
}
