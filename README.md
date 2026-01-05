# usnmpexporter

usnmpexporter is a Prometheus exporter for SNMP devices. It is simplified exporter, as existing [snmp_exporter](https://github.com/prometheus/snmp_exporter) is a bit overcomplicated for such trivial task as graphing just few switches and devices.

## Troubleshooting

If you are not getting the expected metrics, you can use `snmpwalk` to check the OIDs that this exporter uses.

The exporter uses the following OIDs to get interface metrics:

*   `1.3.6.1.2.1.31.1.1.1.1` (ifName)
*   `1.3.6.1.2.1.2.2.1.2` (ifDescr)
*   `1.3.6.1.2.1.31.1.1.1.6` (ifHCInOctets)
*   `1.3.6.1.2.1.31.1.1.1.10` (ifHCOutOctets)

You can use `snmpwalk` to check the values of these OIDs. For example, to get the interface names, you can run:

```
snmpwalk -v 2c -c <community> <device_ip> 1.3.6.1.2.1.31.1.1.1.1
```

Replace `<community>` and `<device_ip>` with your SNMP community and device IP address.

This should give you a list of interface names, similar to what the exporter would get. You can do the same for the other OIDs to debug any issues.

## Custom tags

You can add tags per device in the YAML config and they will be applied to all metrics for that device, including `if*` and `oidmisc` metrics.
