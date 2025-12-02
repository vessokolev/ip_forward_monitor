# Monitoring IPv4 and IPv6 Routed Traffic

This project provides two tools for monitoring IPv4 and IPv6 traffic routed through a Linux system:

1. **`ip_forward_monitor.py`** - Uses `/proc` and `/sys` interfaces (simple, no special privileges)
2. **`monitor_ip_forward_bpf.py`** - Uses eBPF/bpftrace (advanced, requires root)

Both tools provide **simple stateless monitoring** without using `iptables`/`ip6tables`, `nftables`, or any stateful measures. They can monitor traffic in deltas (changes over time) and export all data in JSON format for easy integration with monitoring systems.

**Author:** Veselin Kolev <vlk@lcpe.uni-sofia.bg>,<vesso@ucc.uni-sofia.bg>  
**License:** MIT  
**Copyright:** (c) 2023-2025 Veselin Kolev

## Features

- **Stateless monitoring**: No `iptables`, `ip6tables`, or `nftables` required - uses only `/proc` and `/sys`
- **IPv4 and IPv6 monitoring**: Separate statistics for both address families
- **Per-interface protocol separation**: Shows IPv4, IPv6, and total traffic per interface
- **Forwarding statistics**: Tracks forwarded packets separately from total traffic
- **Continuous monitoring**: Real-time monitoring with configurable intervals
- **Delta calculations**: Shows traffic changes between sampling intervals
- **Rate calculations**: Calculates packets/second rates for forwarded traffic
- **JSON export**: All data can be exported in JSON format with ISO 8601 timestamps
- **Text and JSON output**: Human-readable text or machine-parseable JSON

## Key Files and Directories

### 1. `/proc/net/snmp` - IPv4 SNMP Statistics
This is the **primary source** for IPv4 forwarding statistics:

- **`ForwDatagrams`**: Number of IPv4 datagrams received for forwarding
- **`OutForwDatagrams`**: Number of IPv4 datagrams forwarded
- **`InOctets`**: Total IPv4 octets received (includes forwarded traffic)
- **`OutOctets`**: Total IPv4 octets sent (includes forwarded traffic)
- **`InReceives`**: Total IPv4 datagrams received
- **`OutRequests`**: Total IPv4 datagrams sent

**Example:**
```bash
cat /proc/net/snmp | grep "^Ip:" | awk '{print $1, $8, $9}'  # Shows ForwDatagrams and OutForwDatagrams
```

### 2. `/proc/net/snmp6` - IPv6 SNMP Statistics
This is the **primary source** for IPv6 forwarding statistics:

- **`Ip6InForwDatagrams`**: Number of IPv6 datagrams received for forwarding
- **`Ip6OutForwDatagrams`**: Number of IPv6 datagrams forwarded
- **`Ip6InOctets`**: Total IPv6 octets received (includes forwarded traffic)
- **`Ip6OutOctets`**: Total IPv6 octets sent (includes forwarded traffic)
- **`Ip6InReceives`**: Total IPv6 datagrams received
- **`Ip6OutRequests`**: Total IPv6 datagrams sent

**Example:**
```bash
cat /proc/net/snmp6 | grep -E "Ip6InForwDatagrams|Ip6OutForwDatagrams"
```

### 3. `/sys/class/net/<interface>/statistics/` - Per-Interface Statistics
Provides per-interface byte and packet counts:

- **`rx_bytes`**: Bytes received on interface
- **`tx_bytes`**: Bytes transmitted on interface
- **`rx_packets`**: Packets received on interface
- **`tx_packets`**: Packets transmitted on interface

**Note:** These include ALL traffic (IPv4 + IPv6), so you need to correlate with IPv6-specific counters.

**Example:**
```bash
cat /sys/class/net/eth0/statistics/rx_bytes
cat /sys/class/net/eth0/statistics/tx_bytes
```

### 4. `/proc/net/dev` - Network Device Statistics
Similar to `/sys/class/net/` but in a different format. Shows aggregate statistics per interface.

**Format:** `interface | rx_bytes rx_packets ... | tx_bytes tx_packets ...`

### 5. `/proc/net/if_inet6` - IPv6 Interface Information
Lists all IPv6 addresses configured on interfaces. Useful for identifying which interfaces handle IPv6 traffic.

**Format:** `IPv6-address interface index prefix-length scope flags`

### 6. `/proc/sys/net/ipv4/ip_forward` - IPv4 Forwarding Status
Shows if IPv4 forwarding is enabled (1) or disabled (0).

### 7. `/proc/sys/net/ipv6/conf/all/forwarding` - IPv6 Forwarding Status
Shows if IPv6 forwarding is enabled (1) or disabled (0).

## Limitations

1. **No direct byte count for forwarded traffic**: `/proc/net/snmp6` provides packet counts for forwarded traffic, but not byte counts. To estimate bytes:
   - Monitor interface statistics before/after
   - Correlate with forwarding packet counts
   - Subtract local traffic (if measurable)

2. **Mixed IPv4/IPv6 traffic**: Interface statistics in `/sys/class/net/` include both IPv4 and IPv6. The script attempts to separate them using `nstat` (if available) or by estimating based on system-wide SNMP ratios. If `nstat` is not available, protocol separation may be approximate.

3. **No per-flow information**: These interfaces provide aggregate statistics only, not per-connection or per-flow data.

## Tools

### 1. ip_forward_monitor.py - /proc and /sys Based Monitoring

**Version:** 1.4.2  
**Privileges:** None required (read-only access to /proc and /sys)  
**Method:** Reads kernel SNMP counters from `/proc/net/snmp` and `/proc/net/snmp6`

#### Command-Line Options

Get help and see all available options:
```bash
python3 ip_forward_monitor.py --help
```

**Available options:**
- `--json`: Output in JSON format (can be combined with other options)
- `--interval <seconds>`: Sampling interval in seconds for monitoring mode (default: 10)
- `monitor`: Command to run continuous monitoring (optional, for one-time snapshot omit this)

**Note:** Options can be combined. For example, you can use `--json` and `--interval` together.

#### Usage Examples

The Python script (`ip_forward_monitor.py`) supports both IPv4 and IPv6 monitoring with JSON or text output:

**Show current statistics (text format):**
```bash
python3 ip_forward_monitor.py
```

**Show current statistics (JSON format):**
```bash
python3 ip_forward_monitor.py --json
```

**Monitor traffic continuously (text format):**
```bash
python3 ip_forward_monitor.py monitor
```

**Monitor traffic continuously (JSON format):**
```bash
python3 ip_forward_monitor.py monitor --json
```

**Monitor with custom interval:**
```bash
python3 ip_forward_monitor.py monitor --interval 5
```

**Monitor with custom interval and JSON output (combined options):**
```bash
python3 ip_forward_monitor.py monitor --json --interval 10
```

**Save JSON output to file:**
```bash
python3 ip_forward_monitor.py monitor --json --interval 10 > monitoring_output.json
```

### 2. monitor_ip_forward_bpf.py - eBPF/bpftrace Based Monitoring

**Privileges:** Root required (for eBPF/bpftrace)  
**Method:** Uses eBPF/bpftrace to monitor kernel functions directly  
**Dependencies:** Requires `bpftrace` to be installed

#### Installation

```bash
# Install bpftrace
dnf install bpftrace    # RHEL/CentOS/Fedora
```

#### Command-Line Options

Get help and see all available options:
```bash
python3 monitor_ip_forward_bpf.py --help
```

**Available options:**
- `--json`: Output in JSON format (can be combined with other options)
- `--interval <seconds>`: Sampling interval in seconds (default: 10 for monitor, 1 for snapshot)
- `monitor`: Command to run continuous monitoring (optional, for one-time snapshot omit this)

**Note:** Options can be combined. For example, you can use `--json` and `--interval` together.

#### Usage Examples

**Show current statistics (one-time snapshot, text format):**
```bash
python3 monitor_ip_forward_bpf.py
```

**Show current statistics (one-time snapshot, JSON format):**
```bash
python3 monitor_ip_forward_bpf.py --json
```

**Show current statistics with custom interval:**
```bash
python3 monitor_ip_forward_bpf.py --json --interval 5
```

**Monitor traffic continuously (text format):**
```bash
python3 monitor_ip_forward_bpf.py monitor
```

**Monitor traffic continuously (JSON format):**
```bash
python3 monitor_ip_forward_bpf.py monitor --json
```

**Monitor with custom interval:**
```bash
python3 monitor_ip_forward_bpf.py monitor --interval 5
```

**Monitor with custom interval and JSON output:**
```bash
python3 monitor_ip_forward_bpf.py monitor --json --interval 10
```

#### Differences from ip_forward_monitor.py

| Feature | ip_forward_monitor.py | monitor_ip_forward_bpf.py |
|---------|----------------------|---------------------------|
| **Privileges** | None required | Root required |
| **Data Source** | `/proc`/`/sys` (kernel counters) | eBPF (kernel functions) |
| **Counters from Boot** | Yes (reads existing counters) | No (counts from monitoring start) |
| **Per-Interface Stats** | Yes (via nstat or estimation) | No (system-wide only) |
| **Packet Types** | Forwarding stats only | Incoming, Forwarded, Outgoing |
| **JSON Output** | Yes | Yes |
| **Overhead** | Very low (file reads) | Low (kernel probes) |

**Note:** `monitor_ip_forward_bpf.py` shows activity during the monitoring window (deltas), not cumulative totals from boot. It tracks three packet types: incoming, forwarded, and outgoing packets.

## JSON Output Format

### ip_forward_monitor.py JSON Output

#### Current Statistics Snapshot

When running without `monitor`, the JSON output shows current totals:

```json
{
  "timestamp": "2025-12-02T12:34:56.789000Z",
  "ipv4": {
    "forwarding_enabled": true,
    "forwarding": {
      "incoming_packets": 12345,
      "outgoing_packets": 12340
    },
    "traffic": {
      "bytes_received": 1234567890,
      "bytes_sent": 987654321,
      "packets_received": 123456,
      "packets_sent": 98765
    }
  },
  "ipv6": {
    "forwarding_enabled": true,
    "forwarding": {
      "incoming_packets": 5432,
      "outgoing_packets": 5430
    },
    "traffic": {
      "bytes_received": 987654321,
      "bytes_sent": 123456789,
      "packets_received": 54321,
      "packets_sent": 12345
    }
  },
  "interfaces": {
    "eth0": {
      "ipv4": {
        "rx_bytes": 500000,
        "tx_bytes": 1000000,
        "rx_packets": 500,
        "tx_packets": 1000
      },
      "ipv6": {
        "rx_bytes": 500000,
        "tx_bytes": 1000000,
        "rx_packets": 500,
        "tx_packets": 1000
      },
      "total": {
        "rx_bytes": 1000000,
        "tx_bytes": 2000000,
        "rx_packets": 1000,
        "tx_packets": 2000
      }
    }
  }
}
```

#### Continuous Monitoring Output

When running with `monitor`, the JSON output shows deltas and rates:

```json
{
  "timestamp": "2025-12-02T12:34:56.789000Z",
  "interval_seconds": 10.0,
  "ipv4": {
    "forwarding": {
      "incoming_packets_delta": 100,
      "outgoing_packets_delta": 98,
      "incoming_packets_rate": 10.0,
      "outgoing_packets_rate": 9.8,
      "incoming_packets_total": 12345,
      "outgoing_packets_total": 12340
    },
    "traffic": {
      "bytes_received_delta": 1000000,
      "bytes_sent_delta": 2000000,
      "packets_received_delta": 1000,
      "packets_sent_delta": 2000,
      "bytes_received_total": 1234567890,
      "bytes_sent_total": 987654321,
      "packets_received_total": 123456,
      "packets_sent_total": 98765
    }
  },
  "ipv6": {
    "forwarding": {
      "incoming_packets_delta": 50,
      "outgoing_packets_delta": 48,
      "incoming_packets_rate": 5.0,
      "outgoing_packets_rate": 4.8,
      "incoming_packets_total": 5432,
      "outgoing_packets_total": 5430
    },
    "traffic": {
      "bytes_received_delta": 500000,
      "bytes_sent_delta": 1000000,
      "packets_received_delta": 500,
      "packets_sent_delta": 1000,
      "bytes_received_total": 987654321,
      "bytes_sent_total": 123456789,
      "packets_received_total": 54321,
      "packets_sent_total": 12345
    }
  },
  "interfaces": {
    "eth0": {
      "ipv4": {
        "rx_bytes_delta": 50000,
        "tx_bytes_delta": 100000,
        "rx_packets_delta": 50,
        "tx_packets_delta": 100,
        "rx_bytes_total": 500000,
        "tx_bytes_total": 1000000,
        "rx_packets_total": 500,
        "tx_packets_total": 1000
      },
      "ipv6": {
        "rx_bytes_delta": 50000,
        "tx_bytes_delta": 100000,
        "rx_packets_delta": 50,
        "tx_packets_delta": 100,
        "rx_bytes_total": 500000,
        "tx_bytes_total": 1000000,
        "rx_packets_total": 500,
        "tx_packets_total": 1000
      },
      "total": {
        "rx_bytes_delta": 100000,
        "tx_bytes_delta": 200000,
        "rx_packets_delta": 100,
        "tx_packets_delta": 200,
        "rx_bytes_total": 1000000,
        "tx_bytes_total": 2000000,
        "rx_packets_total": 1000,
        "tx_packets_total": 2000
      }
    }
  }
}
```

**Key points:**
- `timestamp`: ISO 8601 format in UTC (e.g., `2025-12-02T12:34:56.789000Z`)
- `interval_seconds`: Time elapsed since last sample (monitoring mode only)
- `*_delta`: Change in value during the interval (monitoring mode only)
- `*_rate`: Rate in packets/second (monitoring mode only, forwarding stats)
- `*_total`: Cumulative total value (from boot)
- `interfaces`: Per-interface statistics with separate IPv4, IPv6, and total counters

### monitor_ip_forward_bpf.py JSON Output

**One-time snapshot or continuous monitoring:**
```json
{
  "timestamp": "2025-12-02T12:34:56.789000Z",
  "interval_seconds": 5,
  "note": "Activity during 5 second monitoring window",
  "ipv4": {
    "incoming": {
      "packets_delta": 15000
    },
    "forwarded": {
      "packets_delta": 12000
    },
    "outgoing": {
      "packets_delta": 15000
    }
  },
  "ipv6": {
    "incoming": {
      "packets_delta": 10000
    },
    "forwarded": {
      "packets_delta": 8000
    },
    "outgoing": {
      "packets_delta": 10000
    }
  }
}
```

**Key points:**
- `timestamp`: ISO 8601 format in UTC
- `interval_seconds`: Monitoring window duration
- `packets_delta`: Activity during the monitoring window (not cumulative from boot)
- `incoming`: Total packets received
- `forwarded`: Packets being forwarded
- `outgoing`: Total packets sent
- **Note:** Values are deltas (activity during monitoring), not cumulative totals from boot

## Acknowledgments

The author expresses gratitude to:
1. **Sofia University** (https://uni-sofia.bg) for providing the necessary infrastructure to develop and test this script.
2. **OpenIntegra PLC** (https://openintegra.com) for the partial but valuable sponsorship of the development of this script.

## Alternative Approaches

If you need more detailed information:

1. **`ss` command**: Can show IPv6 socket statistics
   ```bash
   ss -6 -s
   ```

2. **`ip -6 -s link show`**: Shows IPv6-specific interface statistics
   ```bash
   ip -6 -s link show
   ```

3. **`nstat` command**: Network statistics tool (if installed)
   ```bash
   nstat -z | grep -i ipv6
   ```
   **Note:** The script uses `nstat` to get per-interface protocol separation when available. Install `iproute2` package to get `nstat`.

4. **eBPF/XDP**: For more advanced monitoring (see `monitor_ip_forward_bpf.py` in this project)

## Protocol Separation

The script attempts to provide separate IPv4 and IPv6 statistics per interface using:

1. **`nstat` command** (preferred): If available, uses `nstat -i <interface> -z` to get per-interface protocol-specific statistics from `/proc/net/netstat`.

2. **Estimation method** (fallback): If `nstat` is not available, estimates protocol distribution based on system-wide SNMP statistics ratios. This is less accurate but provides some separation.

3. **Total only** (last resort): If neither method works, shows only combined totals per interface.

To get accurate per-interface protocol separation, install `iproute2` package which provides the `nstat` command.

## Example: Tracking Forwarded Traffic Over Time

### Using the Python Script

**One-time snapshot:**
```bash
# Capture current state
python3 ip_forward_monitor.py --json > snapshot.json
```

**Continuous monitoring:**
```bash
# Monitor with 10-second intervals (default)
python3 ip_forward_monitor.py monitor --json

# Monitor with 5-second intervals
python3 ip_forward_monitor.py monitor --interval 5 --json

# Save monitoring output to file
python3 ip_forward_monitor.py monitor --interval 5 --json > monitoring.log
```

**Text output for human reading:**
```bash
# Current statistics
python3 ip_forward_monitor.py

# Continuous monitoring
python3 ip_forward_monitor.py monitor --interval 10
```

### Using Bash

```bash
#!/bin/bash
# Capture initial state (IPv6)
INIT_IN_IPV6=$(grep "^Ip6InForwDatagrams" /proc/net/snmp6 | awk '{print $2}')
INIT_OUT_IPV6=$(grep "^Ip6OutForwDatagrams" /proc/net/snmp6 | awk '{print $2}')

# Capture initial state (IPv4)
INIT_IN_IPV4=$(grep "^Ip:" /proc/net/snmp | head -1 | awk '{print $8}')  # ForwDatagrams
INIT_OUT_IPV4=$(grep "^Ip:" /proc/net/snmp | head -1 | awk '{print $9}')  # OutForwDatagrams

# Wait or do something
sleep 60

# Capture final state (IPv6)
FINAL_IN_IPV6=$(grep "^Ip6InForwDatagrams" /proc/net/snmp6 | awk '{print $2}')
FINAL_OUT_IPV6=$(grep "^Ip6OutForwDatagrams" /proc/net/snmp6 | awk '{print $2}')

# Capture final state (IPv4)
FINAL_IN_IPV4=$(grep "^Ip:" /proc/net/snmp | head -1 | awk '{print $8}')
FINAL_OUT_IPV4=$(grep "^Ip:" /proc/net/snmp | head -1 | awk '{print $9}')

# Calculate differences
DIFF_IN_IPV6=$((FINAL_IN_IPV6 - INIT_IN_IPV6))
DIFF_OUT_IPV6=$((FINAL_OUT_IPV6 - INIT_OUT_IPV6))
DIFF_IN_IPV4=$((FINAL_IN_IPV4 - INIT_IN_IPV4))
DIFF_OUT_IPV4=$((FINAL_OUT_IPV4 - INIT_OUT_IPV4))

echo "Forwarded packets in last 60 seconds:"
echo "IPv4 - Incoming: $DIFF_IN_IPV4, Outgoing: $DIFF_OUT_IPV4"
echo "IPv6 - Incoming: $DIFF_IN_IPV6, Outgoing: $DIFF_OUT_IPV6"
```

