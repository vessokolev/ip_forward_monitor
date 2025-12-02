#!/usr/bin/env python3
"""
Monitor IPv4 and IPv6 forwarded traffic using eBPF/bpftrace
Provides same interface as ip_forward_monitor.py
"""

import os
import sys
import json
import argparse
import subprocess
import time
from datetime import datetime, timezone


def timestamp_to_iso8601(timestamp):
    """Convert Unix timestamp to ISO 8601 format string"""
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def run_bpftrace_current_stats(json_output=False, interval=1):
    """
    Run bpftrace to get current statistics (one-shot snapshot)
    Uses eBPF to:
    1. Read kernel SNMP counters from boot (via kprobes on SNMP access functions)
    2. Monitor traffic during interval for deltas
    """
    
    # Pure eBPF approach: Track incoming, forwarded, and outgoing packets (deltas only)
    bpftrace_script = """
    // Track all packet types: incoming, forwarded, and outgoing (deltas only)
    
    // IPv4 counters
    kprobe:ip_rcv { @ipv4_incoming_delta++; }  // Total incoming packets
    kprobe:ip_forward { @ipv4_forwarded_delta++; }  // Forwarded packets
    kprobe:ip_finish_output { @ipv4_outgoing_delta++; }  // Total outgoing packets
    
    // IPv6 counters
    kprobe:ipv6_rcv { @ipv6_incoming_delta++; }  // Total incoming packets
    kprobe:ip6_forward { @ipv6_forwarded_delta++; }  // Forwarded packets
    kprobe:ip6_finish_output2 { @ipv6_outgoing_delta++; }  // Total outgoing packets
    
    // Wait for specified interval, then print and exit
    interval:s:INTERVAL_PLACEHOLDER {
        // IPv4 values
        $ipv4_incoming_delta = @ipv4_incoming_delta;
        $ipv4_forwarded_delta = @ipv4_forwarded_delta;
        $ipv4_outgoing_delta = @ipv4_outgoing_delta;
        
        // IPv6 values
        $ipv6_incoming_delta = @ipv6_incoming_delta;
        $ipv6_forwarded_delta = @ipv6_forwarded_delta;
        $ipv6_outgoing_delta = @ipv6_outgoing_delta;
        
        if (JSON_OUTPUT_PLACEHOLDER == 1) {
            printf("JSON:%llu:%llu:%llu:%llu:%llu:%llu\\n",
                $ipv4_incoming_delta, $ipv4_forwarded_delta, $ipv4_outgoing_delta,
                $ipv6_incoming_delta, $ipv6_forwarded_delta, $ipv6_outgoing_delta);
        } else {
            printf("=== Current IPv4 & IPv6 Statistics ===\\n");
            printf("IPv4 - Incoming packets: %llu\\n", $ipv4_incoming_delta);
            printf("IPv4 - Forwarded packets: %llu\\n", $ipv4_forwarded_delta);
            printf("IPv4 - Outgoing packets: %llu\\n", $ipv4_outgoing_delta);
            printf("IPv6 - Incoming packets: %llu\\n", $ipv6_incoming_delta);
            printf("IPv6 - Forwarded packets: %llu\\n", $ipv6_forwarded_delta);
            printf("IPv6 - Outgoing packets: %llu\\n", $ipv6_outgoing_delta);
        }
        
        exit();
    }
    """
    
    # Replace placeholders
    script = bpftrace_script.replace('INTERVAL_PLACEHOLDER', str(interval))
    script = script.replace('JSON_OUTPUT_PLACEHOLDER', '1' if json_output else '0')
    
    try:
        # Merge stderr into stdout and filter out bpftrace messages
        proc = subprocess.Popen(
            ['bpftrace', '-e', script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        output_lines = []
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            # Filter out bpftrace stderr messages
            if 'Attaching' in line and 'probes' in line:
                continue
            output_lines.append(line)
        
        proc.wait()
        
        if json_output and output_lines:
            # Parse JSON format from bpftrace
            for line in output_lines:
                if line.startswith('JSON:'):
                    parts = line.split(':')
                    if len(parts) >= 7:
                        data = {
                            'timestamp': timestamp_to_iso8601(time.time()),
                            'interval_seconds': interval,
                            'note': f'Activity during {interval} second monitoring window',
                            'ipv4': {
                                'incoming': {
                                    'packets_delta': int(parts[1]),
                                },
                                'forwarded': {
                                    'packets_delta': int(parts[2]),
                                },
                                'outgoing': {
                                    'packets_delta': int(parts[3]),
                                }
                            },
                            'ipv6': {
                                'incoming': {
                                    'packets_delta': int(parts[4]),
                                },
                                'forwarded': {
                                    'packets_delta': int(parts[5]),
                                },
                                'outgoing': {
                                    'packets_delta': int(parts[6]),
                                }
                            }
                        }
                        print(json.dumps(data, indent=2))
                        return
        else:
            # Text output
            for line in output_lines:
                print(line)
                    
    except FileNotFoundError:
        print("Error: bpftrace not found. Please install bpftrace.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_bpftrace_monitor(interval=10, json_output=False):
    """Run bpftrace monitoring with same interface as ip_forward_monitor.py"""
    
    bpftrace_script = """
    // Track all packet types: incoming, forwarded, and outgoing (deltas only)
    
    // IPv4 counters
    kprobe:ip_rcv { @ipv4_incoming_delta++; }  // Total incoming packets
    kprobe:ip_forward { @ipv4_forwarded_delta++; }  // Forwarded packets
    kprobe:ip_finish_output { @ipv4_outgoing_delta++; }  // Total outgoing packets
    
    // IPv6 counters
    kprobe:ipv6_rcv { @ipv6_incoming_delta++; }  // Total incoming packets
    kprobe:ip6_forward { @ipv6_forwarded_delta++; }  // Forwarded packets
    kprobe:ip6_finish_output2 { @ipv6_outgoing_delta++; }  // Total outgoing packets
    
    interval:s:INTERVAL_PLACEHOLDER {
        // IPv4 values
        $ipv4_incoming_delta = @ipv4_incoming_delta;
        $ipv4_forwarded_delta = @ipv4_forwarded_delta;
        $ipv4_outgoing_delta = @ipv4_outgoing_delta;
        
        // IPv6 values
        $ipv6_incoming_delta = @ipv6_incoming_delta;
        $ipv6_forwarded_delta = @ipv6_forwarded_delta;
        $ipv6_outgoing_delta = @ipv6_outgoing_delta;
        
        if (JSON_OUTPUT_PLACEHOLDER == 1) {
            printf("JSON:%llu:%llu:%llu:%llu:%llu:%llu\\n",
                $ipv4_incoming_delta, $ipv4_forwarded_delta, $ipv4_outgoing_delta,
                $ipv6_incoming_delta, $ipv6_forwarded_delta, $ipv6_outgoing_delta);
        } else {
            printf("=== IPv4 & IPv6 Statistics (interval: %d seconds) ===\\n", INTERVAL_PLACEHOLDER);
            printf("IPv4 - Incoming packets: %llu\\n", $ipv4_incoming_delta);
            printf("IPv4 - Forwarded packets: %llu\\n", $ipv4_forwarded_delta);
            printf("IPv4 - Outgoing packets: %llu\\n", $ipv4_outgoing_delta);
            printf("IPv6 - Incoming packets: %llu\\n", $ipv6_incoming_delta);
            printf("IPv6 - Forwarded packets: %llu\\n", $ipv6_forwarded_delta);
            printf("IPv6 - Outgoing packets: %llu\\n", $ipv6_outgoing_delta);
            printf("--------------------------------------------------\\n");
        }
        
        // Reset counters for next interval
        clear(@ipv4_incoming_delta);
        clear(@ipv4_forwarded_delta);
        clear(@ipv4_outgoing_delta);
        clear(@ipv6_incoming_delta);
        clear(@ipv6_forwarded_delta);
        clear(@ipv6_outgoing_delta);
    }
    """
    
    # Replace placeholders
    script = bpftrace_script.replace('INTERVAL_PLACEHOLDER', str(interval))
    script = script.replace('JSON_OUTPUT_PLACEHOLDER', '1' if json_output else '0')
    
    if not json_output:
        print("=== IPv4 & IPv6 Forwarded Traffic Monitor ===")
        print(f"Sampling interval: {interval} seconds")
        print("Press Ctrl+C to stop")
        print()
    
    try:
        # Merge stderr into stdout and filter out bpftrace messages
        proc = subprocess.Popen(
            ['bpftrace', '-e', script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            # Filter out bpftrace stderr messages
            if 'Attaching' in line and 'probes' in line:
                continue
                
            if json_output and line.startswith('JSON:'):
                # Parse JSON format from bpftrace
                parts = line.split(':')
                if len(parts) >= 7:
                    data = {
                        'timestamp': timestamp_to_iso8601(time.time()),
                        'interval_seconds': interval,
                        'note': f'Activity during {interval} second monitoring window',
                        'ipv4': {
                            'incoming': {
                                'packets_delta': int(parts[1]),
                            },
                            'forwarded': {
                                'packets_delta': int(parts[2]),
                            },
                            'outgoing': {
                                'packets_delta': int(parts[3]),
                            }
                        },
                        'ipv6': {
                            'incoming': {
                                'packets_delta': int(parts[4]),
                            },
                            'forwarded': {
                                'packets_delta': int(parts[5]),
                            },
                            'outgoing': {
                                'packets_delta': int(parts[6]),
                            }
                        }
                    }
                    print(json.dumps(data, indent=2))
            else:
                # Text output
                print(line)
        
        proc.wait()
        
    except KeyboardInterrupt:
        if not json_output:
            print("\nMonitoring stopped")
        proc.terminate()
    except FileNotFoundError:
        print("Error: bpftrace not found. Please install bpftrace.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Monitor IPv4 and IPv6 forwarded traffic using eBPF/bpftrace',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s monitor                 # Monitor traffic continuously (text format)
  %(prog)s monitor --json          # Monitor traffic continuously (JSON format)
  %(prog)s monitor --interval 5    # Monitor with 5 second interval
  %(prog)s monitor --json --interval 10  # Monitor with JSON output and 10s interval
        """
    )
    parser.add_argument('command', nargs='?', choices=['monitor'],
                       help='Command to run (monitor for continuous monitoring, omit for one-time snapshot)')
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    parser.add_argument('--interval', type=int, default=None,
                       help='Sampling interval in seconds (default: 10 for monitor, 1 for snapshot)')
    
    args = parser.parse_args()
    
    if args.command == 'monitor':
        interval = args.interval if args.interval is not None else 10
        run_bpftrace_monitor(interval, args.json)
    else:
        # Show current statistics (one-time snapshot using eBPF)
        # Use interval if specified, otherwise default to 1 second for snapshot
        interval = args.interval if args.interval is not None else 1
        run_bpftrace_current_stats(args.json, interval)

