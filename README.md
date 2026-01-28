# usnmpexporter

usnmpexporter is a Prometheus exporter for SNMP devices. It is simplified exporter, as existing [snmp_exporter](https://github.com/prometheus/snmp_exporter) is a bit overcomplicated for such trivial task as graphing just few switches and devices.

## Troubleshooting

If you are not getting the expected metrics, you can use `snmpwalk` to check the OIDs that this exporter uses.

The exporter uses the following OIDs to get interface metrics:

*   `1.3.6.1.2.1.31.1.1.1.1` (ifName)
*   `1.3.6.1.2.1.2.2.1.2` (ifDescr)
*   `1.3.6.1.2.1.31.1.1.1.6` (ifHCInOctets)
*   `1.3.6.1.2.1.31.1.1.1.10` (ifHCOutOctets)
*   `1.3.6.1.2.1.31.1.1.1.18` (ifAlias) - optional, see below

You can use `snmpwalk` to check the values of these OIDs. For example, to get the interface names, you can run:

```
snmpwalk -v 2c -c <community> <device_ip> 1.3.6.1.2.1.31.1.1.1.1
```

Replace `<community>` and `<device_ip>` with your SNMP community and device IP address.

This should give you a list of interface names, similar to what the exporter would get. You can do the same for the other OIDs to debug any issues.

## Custom tags

You can add tags per device in the YAML config and they will be applied to all metrics for that device, including `if*` and `oidmisc` metrics.

## Interface Alias (ifAlias)

The exporter can optionally fetch the `ifAlias` OID (1.3.6.1.2.1.31.1.1.1.18), which contains the admin-set interface description. This is useful when you want to include human-readable port descriptions in your metrics (e.g., "Uplink to Core", "Customer: ACME Corp").

To enable this feature, add `fetch_ifalias: true` to a device in your config:

```yaml
- ip: 192.168.1.1
  community: public
  version: 2c
  fetch_ifalias: true
```

When enabled, metrics will include an `ifAlias` label:

```
ifHCInOctets{host="192.168.1.1",ifName="ge-0/0/0",ifDescr="ge-0/0/0",ifIndex="500",ifAlias="Uplink to Core"} 123456
```

The `ifAlias` label is only included when:
- `fetch_ifalias: true` is set for the device
- The interface has a non-empty alias configured

Special characters in the alias value are minimally sanitized:
- Backslash (`\`) is replaced with `_`
- Double quote (`"`) is replaced with `_`
- Newline is replaced with `_`

To check ifAlias values on a device:

```
snmpwalk -v 2c -c <community> <device_ip> 1.3.6.1.2.1.31.1.1.1.18
```
