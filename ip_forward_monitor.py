#!/usr/bin/env python3
"""
Monitor IPv4 and IPv6 forwarded traffic using /proc and /sys
Provides continuous monitoring and calculates traffic deltas
Supports both JSON and text output formats
"""

# Author: Veselin Kolev <vlk@lcpe.uni-sofia.bg>,<vesso@ucc.uni-sofia.bg>
# Date: 2025-12-02
# Version: 1.4.2
# Description: Monitor IPv4 and IPv6 forwarded traffic using /proc and /sys
# License: MIT
# Copyright (c) 2023-2025 Veselin Kolev
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# Acknowledgments: The author want to express his gratitude to:
#    1. Sofia University for providing the necessary infrastructure to develop and test this script.
#    2. OpenIntegra PLC for the partial but valuable sponsorship of the development of this script.

# TODO: Large part of the statements might be refactored to use functions and classes.
#       Some statements might be organised in loops.
#       Check if the script works with Python 3.10 and above

import os
import time
import sys
import json
import argparse
import subprocess
import re
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Any


def timestamp_to_iso8601(timestamp: float) -> str:
    # 2025-12-02 by Vesso: I finally found time to add timestamp to the output.
    # Fixing the timezone issue: https://stackoverflow.com/questions/51959231/python-datetime-timezone-and-utc
    """Convert Unix timestamp to ISO 8601 format string"""
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def read_snmp6_stats() -> Dict[str, int]:
    """Read IPv6 SNMP statistics from /proc/net/snmp6"""
    stats = {}
    try:
        with open('/proc/net/snmp6', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    stats[parts[0]] = int(parts[1])
    except FileNotFoundError:
        pass  # Silently fail if file doesn't exist
    except Exception as e:
        pass  # Silently fail on errors
    return stats


def read_snmp4_stats() -> Dict[str, int]:
    """Read IPv4 SNMP statistics from /proc/net/snmp"""
    stats = {}
    try:
        with open('/proc/net/snmp', 'r') as f:
            lines = f.readlines()
            # Find the Ip line (second occurrence is the actual stats)
            ip_lines = [line for line in lines if line.startswith('Ip:')]
            if len(ip_lines) >= 2:
                # First line is header, second is values
                headers = ip_lines[0].strip().split()
                values = ip_lines[1].strip().split()
                # Skip 'Ip:' prefix
                for i in range(1, min(len(headers), len(values))):
                    try:
                        stats[headers[i]] = int(values[i])
                    except (ValueError, IndexError):
                        pass
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    return stats


def get_interface_stats(ifname: str) -> Optional[Dict[str, int]]:
    """Get statistics for a specific interface from /sys/class/net/"""
    base_path = f'/sys/class/net/{ifname}/statistics'
    stats = {}
    
    for stat in ['rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets']:
        stat_path = f'{base_path}/{stat}'
        try:
            with open(stat_path, 'r') as f:
                stats[stat] = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            return None
    
    return stats


def get_interface_protocol_stats(ifname: str) -> Optional[Dict[str, Dict[str, int]]]:
    """
    Get separate IPv4 and IPv6 statistics for an interface.
    Uses 'ip -s -s link show' to read kernel statistics (not stateful).
    Falls back to /sys/class/net/ for totals if ip command fails.
    """
    # Get total stats from /sys as baseline
    total_stats = get_interface_stats(ifname)
    if not total_stats:
        return None
    
    result = {
        'ipv4': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
        'ipv6': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
        'total': total_stats
    }
    
    # Try using 'ip -s -s link show' for detailed stats
    # Note: Standard ip command may not always separate IPv4/IPv6 per interface
    # But we'll try to parse what we can get
    try:
        ip_result = subprocess.run(
            ['ip', '-s', '-s', 'link', 'show', ifname],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5
        )
        
        if ip_result.returncode == 0:
            # Parse ip output - it shows RX/TX statistics
            # Format varies, but typically shows bytes and packets
            lines = ip_result.stdout.split('\n')
            
            # Look for RX and TX sections
            for i, line in enumerate(lines):
                if 'RX:' in line or 'rx_bytes' in line.lower():
                    # Parse RX statistics
                    # Format: RX: bytes packets errors dropped ...
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            rx_bytes = int(parts[1])
                            rx_packets = int(parts[2])
                            # These are totals, not separated by protocol
                        except (ValueError, IndexError):
                            pass
                
                elif 'TX:' in line or 'tx_bytes' in line.lower():
                    # Parse TX statistics
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            tx_bytes = int(parts[1])
                            tx_packets = int(parts[2])
                            # These are totals, not separated by protocol
                        except (ValueError, IndexError):
                            pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    # Try using nstat if available (reads from /proc/net/netstat)
    try:
        nstat_result = subprocess.run(
            ['nstat', '-i', ifname, '-z'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5
        )
        
        if nstat_result.returncode == 0:
            # Parse nstat output
            # nstat can show per-interface protocol-specific stats
            for line in nstat_result.stdout.split('\n'):
                line = line.strip()
                # Look for IPv4/IPv6 specific counters
                # Format: InterfaceName/StatName value
                if '/IpInReceives' in line or '/Ip6InReceives' in line:
                    # Extract IPv4/IPv6 receive stats
                    pass
                elif '/IpOutRequests' in line or '/Ip6OutRequests' in line:
                    # Extract IPv4/IPv6 send stats
                    pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    # Since /proc and /sys don't directly provide per-interface protocol separation,
    # we need to use kernel statistics via ip/nstat commands.
    # As a workaround, we can try to read from /proc/net/dev and correlate,
    # but that's also combined.
    
    # For now, return totals with protocol stats as 0 (to be filled by correlation)
    # The user will need to use monitoring over time or accept that
    # per-interface protocol separation requires tools beyond basic /proc/sys
    
    return result


def get_ipv6_interfaces() -> list:
    """Get list of interfaces with IPv6 addresses"""
    interfaces = set()
    try:
        with open('/proc/net/if_inet6', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    # Interface name is in the second field (index)
                    # We need to map index to name, but for simplicity,
                    # we'll get all interfaces from /sys/class/net
                    pass
    except FileNotFoundError:
        pass
    
    # Get all interfaces from /sys/class/net
    try:
        for item in os.listdir('/sys/class/net'):
            if item != 'lo':  # Skip loopback
                interfaces.add(item)
    except Exception:
        pass
    
    return sorted(interfaces)


def is_ipv6_forwarding_enabled() -> bool:
    """Check if IPv6 forwarding is enabled"""
    try:
        with open('/proc/sys/net/ipv6/conf/all/forwarding', 'r') as f:
            return f.read().strip() == '1'
    except Exception:
        return False


def is_ipv4_forwarding_enabled() -> bool:
    """Check if IPv4 forwarding is enabled"""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            return f.read().strip() == '1'
    except Exception:
        return False


def format_bytes(bytes_count: int) -> str:
    """Format byte count in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def get_interface_protocol_stats_nstat(ifname: str) -> Optional[Dict[str, Dict[str, int]]]:
    """
    Get separate IPv4 and IPv6 statistics using nstat (reads from /proc/net/netstat).
    Returns None if nstat is not available or doesn't support per-interface stats.
    """
    # Get totals from /sys first
    total_stats = get_interface_stats(ifname)
    if not total_stats:
        return None
    
    stats = {
        'ipv4': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
        'ipv6': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
        'total': total_stats
    }
    
    try:
        # Try nstat with per-interface option
        # Note: nstat format varies, try different approaches
        result = subprocess.run(
            ['nstat', '-i', ifname, '-z'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            # Parse nstat output - format can be:
            # InterfaceName/StatName value
            # or just StatName value (system-wide)
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Try to parse different formats
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                stat_name = parts[0]
                try:
                    value = int(parts[-1])
                except ValueError:
                    continue
                
                # Check for per-interface stats (format: ifname/StatName)
                if '/' in stat_name:
                    ifname_part, stat_part = stat_name.split('/', 1)
                    if ifname_part != ifname:
                        continue
                else:
                    # System-wide stat, skip for per-interface
                    continue
                
                # Parse IPv4 stats
                if 'IpInReceives' in stat_part:
                    stats['ipv4']['rx_packets'] = value
                elif 'IpInOctets' in stat_part:
                    stats['ipv4']['rx_bytes'] = value
                elif 'IpOutRequests' in stat_part:
                    stats['ipv4']['tx_packets'] = value
                elif 'IpOutOctets' in stat_part:
                    stats['ipv4']['tx_bytes'] = value
                # Parse IPv6 stats
                elif 'Ip6InReceives' in stat_part:
                    stats['ipv6']['rx_packets'] = value
                elif 'Ip6InOctets' in stat_part:
                    stats['ipv6']['rx_bytes'] = value
                elif 'Ip6OutRequests' in stat_part:
                    stats['ipv6']['tx_packets'] = value
                elif 'Ip6OutOctets' in stat_part:
                    stats['ipv6']['tx_bytes'] = value
        
        # If we got any protocol-specific stats, return them
        if (stats['ipv4']['rx_bytes'] > 0 or stats['ipv4']['tx_bytes'] > 0 or
            stats['ipv6']['rx_bytes'] > 0 or stats['ipv6']['tx_bytes'] > 0):
            return stats
        
        # If nstat doesn't provide per-interface stats, try alternative approach
        # Use system-wide SNMP stats and estimate based on interface totals
        # This is not accurate but better than nothing
        ipv4_snmp = read_snmp4_stats()
        ipv6_snmp = read_snmp6_stats()
        
        if ipv4_snmp and ipv6_snmp:
            # Calculate system-wide totals
            total_ipv4_packets = ipv4_snmp.get('InReceives', 0) + ipv4_snmp.get('OutRequests', 0)
            total_ipv6_packets = ipv6_snmp.get('Ip6InReceives', 0) + ipv6_snmp.get('Ip6OutRequests', 0)
            total_system_packets = total_ipv4_packets + total_ipv6_packets
            
            if total_system_packets > 0:
                # Estimate protocol distribution based on system-wide ratios
                # This is a rough approximation
                ipv4_ratio = total_ipv4_packets / total_system_packets
                ipv6_ratio = total_ipv6_packets / total_system_packets
                
                total_packets = total_stats['rx_packets'] + total_stats['tx_packets']
                estimated_ipv4_packets = int(total_packets * ipv4_ratio)
                estimated_ipv6_packets = int(total_packets * ipv6_ratio)
                
                # Distribute bytes and packets proportionally
                total_bytes = total_stats['rx_bytes'] + total_stats['tx_bytes']
                stats['ipv4']['rx_packets'] = int(total_stats['rx_packets'] * ipv4_ratio)
                stats['ipv4']['tx_packets'] = int(total_stats['tx_packets'] * ipv4_ratio)
                stats['ipv4']['rx_bytes'] = int(total_stats['rx_bytes'] * ipv4_ratio)
                stats['ipv4']['tx_bytes'] = int(total_stats['tx_bytes'] * ipv4_ratio)
                
                stats['ipv6']['rx_packets'] = int(total_stats['rx_packets'] * ipv6_ratio)
                stats['ipv6']['tx_packets'] = int(total_stats['tx_packets'] * ipv6_ratio)
                stats['ipv6']['rx_bytes'] = int(total_stats['rx_bytes'] * ipv6_ratio)
                stats['ipv6']['tx_bytes'] = int(total_stats['tx_bytes'] * ipv6_ratio)
                
                return stats
        
        # Return stats with totals (protocol separation not available)
        return stats
        
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # nstat not available, return totals only
        return stats


def collect_all_stats() -> Dict[str, Any]:
    """Collect all IPv4 and IPv6 statistics with per-interface protocol separation"""
    ipv4_stats = read_snmp4_stats()
    ipv6_stats = read_snmp6_stats()
    
    interfaces = get_ipv6_interfaces()
    interface_data = {}
    
    for ifname in interfaces:
        # Try to get protocol-separated stats using nstat
        proto_stats = get_interface_protocol_stats_nstat(ifname)
        
        if proto_stats:
            # We have protocol-separated stats
            interface_data[ifname] = proto_stats
        else:
            # Fallback to total stats only
            if_stats = get_interface_stats(ifname)
            if if_stats:
                interface_data[ifname] = {
                    'ipv4': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
                    'ipv6': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
                    'total': if_stats
                }
    
    return {
        'ipv4': {
            'forwarding_enabled': is_ipv4_forwarding_enabled(),
            'stats': ipv4_stats,
        },
        'ipv6': {
            'forwarding_enabled': is_ipv6_forwarding_enabled(),
            'stats': ipv6_stats,
        },
        'interfaces': interface_data,
        'timestamp': time.time()
    }


def format_stats_for_json(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Format statistics for JSON output"""
    result = {
        'timestamp': timestamp_to_iso8601(stats['timestamp']),
        'ipv4': {
            'forwarding_enabled': stats['ipv4']['forwarding_enabled'],
            'forwarding': {
                'incoming_packets': stats['ipv4']['stats'].get('ForwDatagrams', 0),
                'outgoing_packets': stats['ipv4']['stats'].get('OutForwDatagrams', 0),
            },
            'traffic': {
                'bytes_received': stats['ipv4']['stats'].get('InOctets', 0),
                'bytes_sent': stats['ipv4']['stats'].get('OutOctets', 0),
                'packets_received': stats['ipv4']['stats'].get('InReceives', 0),
                'packets_sent': stats['ipv4']['stats'].get('OutRequests', 0),
            }
        },
        'ipv6': {
            'forwarding_enabled': stats['ipv6']['forwarding_enabled'],
            'forwarding': {
                'incoming_packets': stats['ipv6']['stats'].get('Ip6InForwDatagrams', 0),
                'outgoing_packets': stats['ipv6']['stats'].get('Ip6OutForwDatagrams', 0),
            },
            'traffic': {
                'bytes_received': stats['ipv6']['stats'].get('Ip6InOctets', 0),
                'bytes_sent': stats['ipv6']['stats'].get('Ip6OutOctets', 0),
                'packets_received': stats['ipv6']['stats'].get('Ip6InReceives', 0),
                'packets_sent': stats['ipv6']['stats'].get('Ip6OutRequests', 0),
            }
        },
        'interfaces': {}
    }
    
    # Format interface stats with protocol separation
    for ifname, if_stats in stats['interfaces'].items():
        if 'ipv4' in if_stats and 'ipv6' in if_stats:
            result['interfaces'][ifname] = {
                'ipv4': if_stats['ipv4'],
                'ipv6': if_stats['ipv6'],
                'total': if_stats.get('total', {})
            }
        else:
            # Fallback format
            result['interfaces'][ifname] = {
                'ipv4': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
                'ipv6': {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0},
                'total': if_stats
            }
    
    return result


def monitor_forwarded_traffic(interval: int = 10, json_output: bool = False):
    """Monitor IPv4 and IPv6 forwarded traffic over time"""
    
    if not json_output:
        if not is_ipv4_forwarding_enabled():
            print("Warning: IPv4 forwarding is not enabled")
        if not is_ipv6_forwarding_enabled():
            print("Warning: IPv6 forwarding is not enabled")
        print()
        print("=== IPv4 & IPv6 Forwarded Traffic Monitor ===")
        print(f"Sampling interval: {interval} seconds")
        print("Press Ctrl+C to stop")
        print()
    
    # Initial snapshot
    prev_stats = collect_all_stats()
    prev_time = time.time()
    
    try:
        while True:
            time.sleep(interval)
            
            current_stats = collect_all_stats()
            current_time = time.time()
            elapsed = current_time - prev_time
            
            if json_output:
                # JSON output for monitoring
                delta_data = {
                    'timestamp': timestamp_to_iso8601(current_time),
                    'interval_seconds': elapsed,
                    'ipv4': {
                        'forwarding': {
                            'incoming_packets_delta': 0,
                            'outgoing_packets_delta': 0,
                            'incoming_packets_rate': 0.0,
                            'outgoing_packets_rate': 0.0,
                            'incoming_packets_total': 0,
                            'outgoing_packets_total': 0,
                        },
                        'traffic': {
                            'bytes_received_delta': 0,
                            'bytes_sent_delta': 0,
                            'packets_received_delta': 0,
                            'packets_sent_delta': 0,
                            'bytes_received_total': 0,
                            'bytes_sent_total': 0,
                            'packets_received_total': 0,
                            'packets_sent_total': 0,
                        }
                    },
                    'ipv6': {
                        'forwarding': {
                            'incoming_packets_delta': 0,
                            'outgoing_packets_delta': 0,
                            'incoming_packets_rate': 0.0,
                            'outgoing_packets_rate': 0.0,
                            'incoming_packets_total': 0,
                            'outgoing_packets_total': 0,
                        },
                        'traffic': {
                            'bytes_received_delta': 0,
                            'bytes_sent_delta': 0,
                            'packets_received_delta': 0,
                            'packets_sent_delta': 0,
                            'bytes_received_total': 0,
                            'bytes_sent_total': 0,
                            'packets_received_total': 0,
                            'packets_sent_total': 0,
                        }
                    },
                    'interfaces': {}
                }
                
                # IPv4 forwarding deltas
                prev_ipv4_forw = prev_stats['ipv4']['stats'].get('ForwDatagrams', 0)
                curr_ipv4_forw = current_stats['ipv4']['stats'].get('ForwDatagrams', 0)
                prev_ipv4_out_forw = prev_stats['ipv4']['stats'].get('OutForwDatagrams', 0)
                curr_ipv4_out_forw = current_stats['ipv4']['stats'].get('OutForwDatagrams', 0)
                
                # 2025-12-02 by Vesso: I wonder if we can implement here loop of lamnbdas. Now it is quite explicit as
                # a list of assignments.
                delta_data['ipv4']['forwarding']['incoming_packets_delta'] = curr_ipv4_forw - prev_ipv4_forw
                delta_data['ipv4']['forwarding']['outgoing_packets_delta'] = curr_ipv4_out_forw - prev_ipv4_out_forw
                delta_data['ipv4']['forwarding']['incoming_packets_rate'] = (curr_ipv4_forw - prev_ipv4_forw) / elapsed if elapsed > 0 else 0.0
                delta_data['ipv4']['forwarding']['outgoing_packets_rate'] = (curr_ipv4_out_forw - prev_ipv4_out_forw) / elapsed if elapsed > 0 else 0.0
                delta_data['ipv4']['forwarding']['incoming_packets_total'] = curr_ipv4_forw
                delta_data['ipv4']['forwarding']['outgoing_packets_total'] = curr_ipv4_out_forw
                
                # IPv4 total traffic deltas
                prev_ipv4_in_bytes = prev_stats['ipv4']['stats'].get('InOctets', 0)
                curr_ipv4_in_bytes = current_stats['ipv4']['stats'].get('InOctets', 0)
                prev_ipv4_out_bytes = prev_stats['ipv4']['stats'].get('OutOctets', 0)
                curr_ipv4_out_bytes = current_stats['ipv4']['stats'].get('OutOctets', 0)
                prev_ipv4_in_pkts = prev_stats['ipv4']['stats'].get('InReceives', 0)
                curr_ipv4_in_pkts = current_stats['ipv4']['stats'].get('InReceives', 0)
                prev_ipv4_out_pkts = prev_stats['ipv4']['stats'].get('OutRequests', 0)
                curr_ipv4_out_pkts = current_stats['ipv4']['stats'].get('OutRequests', 0)
                
                # 2025-12-02 by Vesso: I wonder if we can implement here loop of lamnbdas. Now it is quite explicit as
                # a list of assignments.
                delta_data['ipv4']['traffic']['bytes_received_delta'] = curr_ipv4_in_bytes - prev_ipv4_in_bytes
                delta_data['ipv4']['traffic']['bytes_sent_delta'] = curr_ipv4_out_bytes - prev_ipv4_out_bytes
                delta_data['ipv4']['traffic']['packets_received_delta'] = curr_ipv4_in_pkts - prev_ipv4_in_pkts
                delta_data['ipv4']['traffic']['packets_sent_delta'] = curr_ipv4_out_pkts - prev_ipv4_out_pkts
                delta_data['ipv4']['traffic']['bytes_received_total'] = curr_ipv4_in_bytes
                delta_data['ipv4']['traffic']['bytes_sent_total'] = curr_ipv4_out_bytes
                delta_data['ipv4']['traffic']['packets_received_total'] = curr_ipv4_in_pkts
                delta_data['ipv4']['traffic']['packets_sent_total'] = curr_ipv4_out_pkts
                
                # IPv6 forwarding deltas
                prev_ipv6_in_forw = prev_stats['ipv6']['stats'].get('Ip6InForwDatagrams', 0)
                curr_ipv6_in_forw = current_stats['ipv6']['stats'].get('Ip6InForwDatagrams', 0)
                prev_ipv6_out_forw = prev_stats['ipv6']['stats'].get('Ip6OutForwDatagrams', 0)
                curr_ipv6_out_forw = current_stats['ipv6']['stats'].get('Ip6OutForwDatagrams', 0)
                
                # 2025-12-02 by Vesso: I wonder if we can implement here loop of lamnbdas. Now it is quite explicit as
                # a list of assignments.
                delta_data['ipv6']['forwarding']['incoming_packets_delta'] = curr_ipv6_in_forw - prev_ipv6_in_forw
                delta_data['ipv6']['forwarding']['outgoing_packets_delta'] = curr_ipv6_out_forw - prev_ipv6_out_forw
                delta_data['ipv6']['forwarding']['incoming_packets_rate'] = (curr_ipv6_in_forw - prev_ipv6_in_forw) / elapsed if elapsed > 0 else 0.0
                delta_data['ipv6']['forwarding']['outgoing_packets_rate'] = (curr_ipv6_out_forw - prev_ipv6_out_forw) / elapsed if elapsed > 0 else 0.0
                delta_data['ipv6']['forwarding']['incoming_packets_total'] = curr_ipv6_in_forw
                delta_data['ipv6']['forwarding']['outgoing_packets_total'] = curr_ipv6_out_forw
                
                # IPv6 total traffic deltas
                prev_ipv6_in_bytes = prev_stats['ipv6']['stats'].get('Ip6InOctets', 0)
                curr_ipv6_in_bytes = current_stats['ipv6']['stats'].get('Ip6InOctets', 0)
                prev_ipv6_out_bytes = prev_stats['ipv6']['stats'].get('Ip6OutOctets', 0)
                curr_ipv6_out_bytes = current_stats['ipv6']['stats'].get('Ip6OutOctets', 0)
                prev_ipv6_in_pkts = prev_stats['ipv6']['stats'].get('Ip6InReceives', 0)
                curr_ipv6_in_pkts = current_stats['ipv6']['stats'].get('Ip6InReceives', 0)
                prev_ipv6_out_pkts = prev_stats['ipv6']['stats'].get('Ip6OutRequests', 0)
                curr_ipv6_out_pkts = current_stats['ipv6']['stats'].get('Ip6OutRequests', 0)
                
                # 2025-12-02 by Vesso: I wonder if we can implement here loop of lamnbdas. Now it is quite explicit as
                # a list of assignments.
                delta_data['ipv6']['traffic']['bytes_received_delta'] = curr_ipv6_in_bytes - prev_ipv6_in_bytes
                delta_data['ipv6']['traffic']['bytes_sent_delta'] = curr_ipv6_out_bytes - prev_ipv6_out_bytes
                delta_data['ipv6']['traffic']['packets_received_delta'] = curr_ipv6_in_pkts - prev_ipv6_in_pkts
                delta_data['ipv6']['traffic']['packets_sent_delta'] = curr_ipv6_out_pkts - prev_ipv6_out_pkts
                delta_data['ipv6']['traffic']['bytes_received_total'] = curr_ipv6_in_bytes
                delta_data['ipv6']['traffic']['bytes_sent_total'] = curr_ipv6_out_bytes
                delta_data['ipv6']['traffic']['packets_received_total'] = curr_ipv6_in_pkts
                delta_data['ipv6']['traffic']['packets_sent_total'] = curr_ipv6_out_pkts
                
                # Interface statistics deltas
                prev_interfaces = prev_stats.get('interfaces', {})
                curr_interfaces = current_stats.get('interfaces', {})
                
                all_ifnames = set(list(prev_interfaces.keys()) + list(curr_interfaces.keys()))
                
                for ifname in all_ifnames:
                    prev_if = prev_interfaces.get(ifname, {})
                    curr_if = curr_interfaces.get(ifname, {})
                    
                    if_data = {
                        'ipv4': {
                            'rx_bytes_delta': 0,
                            'tx_bytes_delta': 0,
                            'rx_packets_delta': 0,
                            'tx_packets_delta': 0,
                            'rx_bytes_total': 0,
                            'tx_bytes_total': 0,
                            'rx_packets_total': 0,
                            'tx_packets_total': 0,
                        },
                        'ipv6': {
                            'rx_bytes_delta': 0,
                            'tx_bytes_delta': 0,
                            'rx_packets_delta': 0,
                            'tx_packets_delta': 0,
                            'rx_bytes_total': 0,
                            'tx_bytes_total': 0,
                            'rx_packets_total': 0,
                            'tx_packets_total': 0,
                        },
                        'total': {
                            'rx_bytes_delta': 0,
                            'tx_bytes_delta': 0,
                            'rx_packets_delta': 0,
                            'tx_packets_delta': 0,
                            'rx_bytes_total': 0,
                            'tx_bytes_total': 0,
                            'rx_packets_total': 0,
                            'tx_packets_total': 0,
                        }
                    }
                    
                    # Calculate deltas for each protocol
                    for proto in ['ipv4', 'ipv6', 'total']:
                        prev_proto = prev_if.get(proto, {})
                        curr_proto = curr_if.get(proto, {})
                        
                        # 2025-12-02 by Vesso: I wonder if we can implement here loop of lamnbdas. Now it is quite explicit as
                        # a list of assignments.
                        if_data[proto]['rx_bytes_delta'] = curr_proto.get('rx_bytes', 0) - prev_proto.get('rx_bytes', 0)
                        if_data[proto]['tx_bytes_delta'] = curr_proto.get('tx_bytes', 0) - prev_proto.get('tx_bytes', 0)
                        if_data[proto]['rx_packets_delta'] = curr_proto.get('rx_packets', 0) - prev_proto.get('rx_packets', 0)
                        if_data[proto]['tx_packets_delta'] = curr_proto.get('tx_packets', 0) - prev_proto.get('tx_packets', 0)
                        if_data[proto]['rx_bytes_total'] = curr_proto.get('rx_bytes', 0)
                        if_data[proto]['tx_bytes_total'] = curr_proto.get('tx_bytes', 0)
                        if_data[proto]['rx_packets_total'] = curr_proto.get('rx_packets', 0)
                        if_data[proto]['tx_packets_total'] = curr_proto.get('tx_packets', 0)
                    
                    delta_data['interfaces'][ifname] = if_data
                
                print(json.dumps(delta_data, indent=2))
            else:
                # Text output
                # IPv4 statistics
                prev_ipv4_forw = prev_stats['ipv4']['stats'].get('ForwDatagrams', 0)
                curr_ipv4_forw = current_stats['ipv4']['stats'].get('ForwDatagrams', 0)
                prev_ipv4_out_forw = prev_stats['ipv4']['stats'].get('OutForwDatagrams', 0)
                curr_ipv4_out_forw = current_stats['ipv4']['stats'].get('OutForwDatagrams', 0)
                
                in_delta = curr_ipv4_forw - prev_ipv4_forw
                in_rate = in_delta / elapsed if elapsed > 0 else 0
                print(f"IPv4 - Incoming forwarded packets: {in_delta} ({in_rate:.2f} pps)")
                print(f"  Total incoming forwarded: {curr_ipv4_forw:,}")
                
                out_delta = curr_ipv4_out_forw - prev_ipv4_out_forw
                out_rate = out_delta / elapsed if elapsed > 0 else 0
                print(f"IPv4 - Outgoing forwarded packets: {out_delta} ({out_rate:.2f} pps)")
                print(f"  Total outgoing forwarded: {curr_ipv4_out_forw:,}")
                
                # IPv6 statistics
                prev_ipv6_in_forw = prev_stats['ipv6']['stats'].get('Ip6InForwDatagrams', 0)
                curr_ipv6_in_forw = current_stats['ipv6']['stats'].get('Ip6InForwDatagrams', 0)
                prev_ipv6_out_forw = prev_stats['ipv6']['stats'].get('Ip6OutForwDatagrams', 0)
                curr_ipv6_out_forw = current_stats['ipv6']['stats'].get('Ip6OutForwDatagrams', 0)
                
                in_delta = curr_ipv6_in_forw - prev_ipv6_in_forw
                in_rate = in_delta / elapsed if elapsed > 0 else 0
                print(f"IPv6 - Incoming forwarded packets: {in_delta} ({in_rate:.2f} pps)")
                print(f"  Total incoming forwarded: {curr_ipv6_in_forw:,}")
                
                out_delta = curr_ipv6_out_forw - prev_ipv6_out_forw
                out_rate = out_delta / elapsed if elapsed > 0 else 0
                print(f"IPv6 - Outgoing forwarded packets: {out_delta} ({out_rate:.2f} pps)")
                print(f"  Total outgoing forwarded: {curr_ipv6_out_forw:,}")
                
                print("-" * 50)
            
            prev_stats = current_stats
            prev_time = current_time
            
    except KeyboardInterrupt:
        if not json_output:
            print("\nMonitoring stopped")


def show_current_stats(json_output: bool = False):
    """Show current IPv4 and IPv6 forwarding statistics"""
    stats = collect_all_stats()
    
    if json_output:
        formatted = format_stats_for_json(stats)
        print(json.dumps(formatted, indent=2))
        return
    
    # Text output
    print("=== Current IPv4 Forwarding Statistics ===")
    print()
    
    ipv4_stats = stats['ipv4']['stats']
    if not stats['ipv4']['forwarding_enabled']:
        print("Warning: IPv4 forwarding is not enabled")
        print()
    
    # IPv4 forwarding statistics
    if 'ForwDatagrams' in ipv4_stats:
        print(f"Incoming forwarded datagrams: {ipv4_stats['ForwDatagrams']:,}")
    if 'OutForwDatagrams' in ipv4_stats:
        print(f"Outgoing forwarded datagrams: {ipv4_stats['OutForwDatagrams']:,}")
    
    print()
    
    # IPv4 total traffic (includes forwarded)
    if 'InOctets' in ipv4_stats:
        print(f"Total IPv4 bytes received: {format_bytes(ipv4_stats['InOctets'])}")
    if 'OutOctets' in ipv4_stats:
        print(f"Total IPv4 bytes sent: {format_bytes(ipv4_stats['OutOctets'])}")
    
    if 'InReceives' in ipv4_stats:
        print(f"Total IPv4 packets received: {ipv4_stats['InReceives']:,}")
    if 'OutRequests' in ipv4_stats:
        print(f"Total IPv4 packets sent: {ipv4_stats['OutRequests']:,}")
    
    print()
    print("=== Current IPv6 Forwarding Statistics ===")
    print()
    
    ipv6_stats = stats['ipv6']['stats']
    if not stats['ipv6']['forwarding_enabled']:
        print("Warning: IPv6 forwarding is not enabled")
        print()
    
    # IPv6 forwarding statistics
    if 'Ip6InForwDatagrams' in ipv6_stats:
        print(f"Incoming forwarded datagrams: {ipv6_stats['Ip6InForwDatagrams']:,}")
    if 'Ip6OutForwDatagrams' in ipv6_stats:
        print(f"Outgoing forwarded datagrams: {ipv6_stats['Ip6OutForwDatagrams']:,}")
    
    print()
    
    # IPv6 total traffic (includes forwarded)
    if 'Ip6InOctets' in ipv6_stats:
        print(f"Total IPv6 bytes received: {format_bytes(ipv6_stats['Ip6InOctets'])}")
    if 'Ip6OutOctets' in ipv6_stats:
        print(f"Total IPv6 bytes sent: {format_bytes(ipv6_stats['Ip6OutOctets'])}")
    
    if 'Ip6InReceives' in ipv6_stats:
        print(f"Total IPv6 packets received: {ipv6_stats['Ip6InReceives']:,}")
    if 'Ip6OutRequests' in ipv6_stats:
        print(f"Total IPv6 packets sent: {ipv6_stats['Ip6OutRequests']:,}")
    
    print()
    
    # Interface statistics with protocol separation
    print("=== Interface Statistics (per protocol) ===")
    for ifname, if_stats in stats['interfaces'].items():
        print(f"\n{ifname}:")
        
        # Check if we have protocol-separated stats
        if 'ipv4' in if_stats and 'ipv6' in if_stats:
            # Show IPv4 stats
            ipv4 = if_stats['ipv4']
            if ipv4['rx_bytes'] > 0 or ipv4['tx_bytes'] > 0 or ipv4['rx_packets'] > 0 or ipv4['tx_packets'] > 0:
                print(f"  IPv4:")
                print(f"    RX: {format_bytes(ipv4['rx_bytes'])} ({ipv4['rx_packets']:,} packets)")
                print(f"    TX: {format_bytes(ipv4['tx_bytes'])} ({ipv4['tx_packets']:,} packets)")
            
            # Show IPv6 stats
            ipv6 = if_stats['ipv6']
            if ipv6['rx_bytes'] > 0 or ipv6['tx_bytes'] > 0 or ipv6['rx_packets'] > 0 or ipv6['tx_packets'] > 0:
                print(f"  IPv6:")
                print(f"    RX: {format_bytes(ipv6['rx_bytes'])} ({ipv6['rx_packets']:,} packets)")
                print(f"    TX: {format_bytes(ipv6['tx_bytes'])} ({ipv6['tx_packets']:,} packets)")
            
            # Show total stats
            if 'total' in if_stats:
                total = if_stats['total']
                print(f"  Total:")
                print(f"    RX: {format_bytes(total['rx_bytes'])} ({total['rx_packets']:,} packets)")
                print(f"    TX: {format_bytes(total['tx_bytes'])} ({total['tx_packets']:,} packets)")
        else:
            # Fallback: show total stats only
            print(f"  Total (IPv4+IPv6 combined):")
            print(f"    RX: {format_bytes(if_stats['rx_bytes'])} ({if_stats['rx_packets']:,} packets)")
            print(f"    TX: {format_bytes(if_stats['tx_bytes'])} ({if_stats['tx_packets']:,} packets)")
            print(f"    Note: Protocol separation not available (install 'nstat' for per-protocol stats)")


if __name__ == '__main__':
    # 2023-04-25 by Vesso:I will add this here until I can find a better way to do it.
    # TODO: I will add a better way to get help here.
    parser = argparse.ArgumentParser(
        description='Monitor IPv4 and IPv6 forwarded traffic using /proc and /sys',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         # Show current statistics (text format)
  %(prog)s --json                  # Show current statistics (JSON format)
  %(prog)s monitor                 # Monitor traffic continuously (text format)
  %(prog)s monitor --json          # Monitor traffic continuously (JSON format)
  %(prog)s monitor --interval 5    # Monitor with 5 second interval
  %(prog)s monitor --json --interval 10  # Monitor with JSON output and 10s interval
        """
    )
    parser.add_argument('command', nargs='?', choices=['monitor'], 
                       help='Command to run (monitor for continuous monitoring)')
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    parser.add_argument('--interval', type=int, default=10,
                       help='Sampling interval in seconds for monitoring (default: 10)')
    
    args = parser.parse_args()
    
    if args.command == 'monitor':
        monitor_forwarded_traffic(args.interval, args.json)
    else:
        show_current_stats(args.json)

