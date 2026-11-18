# usnmpexporter

usnmpexporter is a Prometheus exporter for SNMP devices. It is simplified exporter, as existing [snmp_exporter](https://github.com/prometheus/snmp_exporter) is a bit overcomplicated for such trivial task as graphing just few switches and devices.

## Docker

`docker-publish.sh` builds the image and pushes it to `nuclearcat/usnmp_exporter`.
The tag comes from `appVersion` in `usnmp_exporter.go`, so bump it there before
releasing; both `<version>` and `latest` are pushed.

```
./docker-publish.sh                                      # build and push
./docker-publish.sh --build-only                         # build locally only
PLATFORMS=linux/amd64,linux/arm64 ./docker-publish.sh     # multi-arch, needs buildx
IMAGE=me/usnmp ./docker-publish.sh                       # different repository
```

You need to be logged in (`docker login`) before pushing.

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

## Slow devices / timeouts

A single unanswered SNMP request costs `timeout * (1 + retries)` before the whole
device scrape is given up, so a device that "fails after 60 seconds" is usually just
hitting that budget rather than being unreachable.

A device that answers nothing at all is cheaper than that: the liveness probe at the
start of a scrape has a separate timeout and runs with retries disabled, so an
unreachable device costs one `probe_timeout` (10s by default) and is then skipped.
The full `timeout * (1 + retries)` budget only applies to a device that answered
the probe and then went silent mid-walk.

Global flags:

*   `-timeout` — SNMP request timeout in seconds (default 20)
*   `-probe-timeout` — liveness probe timeout in seconds (default 10)
*   `-retries` — retries per request (default 2)
*   `-max-repetitions` — GETBULK max-repetitions (default 50), lower it if the device
    drops or truncates large replies
*   `-device-poll-timeout` — optional whole-device deadlines, for example
    `-device-poll-timeout=192.0.2.1=30s,192.0.2.2=1m`

They can be overridden per device in the config:

```yaml
- ip: 10.1.1.1
  community: public
  version: 2c
  timeout: 10
  probe_timeout: 5
  retries: 1
  max_repetitions: 20
```

To change the defaults for all devices, use the mapping form of the config and
put `timeout`, `probe_timeout`, and `retries` at the root. A value on a device
overrides the root default; if neither is present, the command-line flag is used:

```yaml
timeout: 10
probe_timeout: 5
retries: 1
devices:
  - ip: 10.1.1.1
    community: public
    version: 2c
  - ip: 10.1.1.2
    community: public
    version: 2c
    timeout: 30
    probe_timeout: 8
    retries: 0
```

The original top-level device list remains supported.

GETBULK starts at the configured batch size. Decode failures try a smaller
window and then GETNEXT, caching the working fallback. Timeouts return an error
without permanently changing the walk mode. Set `max_repetitions` explicitly
for devices needing smaller batches.

Choose a Prometheus `scrape_timeout` longer than the desired device poll budgets
and a scrape interval longer than that timeout. A whole-device deadline includes
the probe, retries, and all walks. Expiry discards that device's incomplete
samples while retaining successful devices. HTTP cancellation closes outstanding
SNMP connections, and concurrent scrapes cannot overlap polls for the same device.
Without a device deadline, allow for `timeout * (1 + retries)` plus walk time.

### Per-device request settings without changing generated YAML

When an orchestrator regenerates device YAML, use optional CLI overrides:

```sh
-device-request-timeout=192.0.2.1=5s
-device-probe-timeout=192.0.2.1=3s
-device-probe-retries=192.0.2.1=2
-device-max-repetitions=192.0.2.1=10
-device-poll-timeout=192.0.2.1=60s
```

Each flag accepts comma-separated `IP=value` entries. Request and probe
timeouts accept positive Go durations; probe retries accept 0–10 and bulk
repetitions 1–65535. These overrides take precedence over YAML/global defaults
only for matching devices. The ordinary request retry count continues to use
the existing YAML/`-retries` setting. Other devices retain their settings,
including the default liveness probe with no retries.

A request timeout is one unanswered exchange; the whole-device deadline covers
the probe, all retries and all tables. Set the HTTP scrape timeout above that
deadline and the scrape interval above the HTTP timeout. For example, a 60s
device budget fits within a 90s HTTP timeout and a 120s interval.

Temporary request timeouts do **not** permanently downgrade the device to a
smaller bulk mode or GETNEXT. Decode errors retain the smaller-batch fallback.
Repeated packet loss should not turn every subsequent poll into a slow
GETNEXT scan; use an explicit safe batch size for agents needing smaller PDUs.

Failed optional `ifmisc` walks are logged and omitted while already collected
interface traffic remains available. Missing counter columns are omitted,
never synthesized as zero; valid zero counters remain valid measurements.
A failed HC read does not establish lack of HC support or permanently select
32-bit counters. Whole-device deadline expiry still discards the incomplete
device poll, and counters are never served from an old scrape.

## Interface metadata cache

Inventory caching is opt-in. Enable it for all devices with
`-metadata-cache-ttl=10m`, or only selected devices with
`-device-metadata-cache-ttl=192.0.2.1=10m,192.0.2.2=5m`. Per-device values
override the global lifetime, which defaults to `0` (disabled).

The cache reuses `ifDescr`, `ifName`, optional `ifAlias`, and configured
`ifHighSpeed` values. All traffic/packet/error/discard counters, operational
and administrative status, vendor scalars, and vendor table walks remain live
on every poll. Existing interfaces, labels, and metric names are preserved.
Renamed ports, edited descriptions, and speed changes may take up to one cache
lifetime to appear. The cache is in memory and starts empty after a restart.

Enabled devices fetch `sysUpTime`, `ifNumber`, and `ifTableLastChange` together
in one GET. A decreased uptime, changed interface count/table marker, or changed
community/version invalidates the inventory immediately. Agents that do not
support the optional IF-MIB markers use TTL and uptime detection instead.
When uptime cannot be verified, inventory is fetched fresh. Failed, cancelled,
or empty reads are not cached; failed refreshes never substitute expired values.
Counter samples are never reused as fresh measurements.

This removes repeated inventory walks, but does not throttle the remaining
counter walks or guarantee a lower peak device CPU usage. Verbose logging shows
cache hits, row counts, and ages.

Validation:

```sh
go test -race ./...
go vet ./...
```

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
