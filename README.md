# GLPI osquery Inventory

A replacement for GLPI 11's native Inventory and the GLPI Agent, built on
[osquery](https://osquery.io), with live queries across the fleet.

| Path | What |
|---|---|
| `plugin/` | The GLPI plugin (`glpiosquery`). Speaks osquery's TLS remote API, assembles inventory, runs live queries |
| `agent/` | The endpoint agent (Go): supervises a bundled `osqueryd`, self-updates, ships the Linux EDID extension |
| `testdata/protocol/` | Real request captures used as fixtures |

## How it works

The thing running on the endpoint is a stock `osqueryd`. The plugin implements
osquery's own enroll / config / log / distributed endpoints, so any osquery build
can point at GLPI. Scheduled snapshot results are assembled server-side into a
GLPI-native inventory document and handed to `Glpi\Inventory\Inventory`, so
assets land as ordinary Computers with the import rules engine, entity rules and
refused-equipment handling applied. Live queries ride osquery's `distributed`
plugin.

```
stock osqueryd ──HTTPS──▶ glpiosquery ──▶ Glpi\Inventory\Inventory ──▶ Computer, Software,
                                                                       NetworkPort, Volume…
```

**GLPI must be served over HTTPS.** osquery 5.x refuses plain HTTP and no longer
has a `--tls_allow_unsafe` escape hatch. Self-signed or internal-CA setups must
ship the CA to the endpoint; the installers do this.

## Install

```bash
# from the GLPI root — the directory must be named for the plugin key,
# which is not the repository name
git clone https://github.com/bijstaan/glpi-osquery.git plugins/glpiosquery
php bin/console plugin:install -u glpi glpiosquery
php bin/console plugin:activate glpiosquery
```

Create an enrollment secret in **Setup → osquery Inventory**, then point a test
host at it:

```bash
osqueryd \
  --tls_hostname=<your GLPI TLS host> \
  --tls_server_certs=/etc/osquery/glpi-ca.crt \
  --enroll_secret_path=/etc/osquery/enroll.secret \
  --enroll_tls_endpoint=/plugins/glpiosquery/front/enroll.php \
  --config_plugin=tls --config_tls_endpoint=/plugins/glpiosquery/front/config.php \
  --logger_plugin=tls --logger_tls_endpoint=/plugins/glpiosquery/front/log.php \
  --disable_distributed=false --distributed_plugin=tls \
  --distributed_tls_read_endpoint=/plugins/glpiosquery/front/read.php \
  --distributed_tls_write_endpoint=/plugins/glpiosquery/front/write.php \
  --database_path=/var/osquery/osquery.db --disable_watchdog --allow_unsafe
```

The shipped packs collect on 1-hour and 24-hour intervals, so nothing lands
within a short test run; shorten `query_interval` in
`glpi_plugin_glpiosquery_queries` while iterating. Inventory assembly is a cron
task (`osqueryInventory`, every 60s) and waits for an agent's snapshots to settle
for 30s before building a document.

## The agent

```bash
cd agent
./build.sh 1.0.0 all      # all six targets: linux/darwin/windows x amd64/arm64
./build.sh 1.0.0 linux/amd64
```

A bundle is one archive holding the supervisor, the pinned `osqueryd` and, on
Linux, the EDID extension. One versioned artifact is what makes self-update
atomic: `current` points at one directory of binaries tested together.

Native installers wrap the same archive, so what an installer lays down is
byte-identical to what a self-update fetches:

```bash
./packaging/build-deb.sh 1.0.0 amd64        # .deb   (needs dpkg-deb)
./packaging/build-msi.sh 1.0.0 amd64        # .msi   (needs wixl + msitools)
./packaging/build-msi.sh 1.0.0 arm64        # .msi, Windows on ARM
./packaging/build-pkg.sh 1.0.0 universal    # .pkg   (needs macOS + Xcode CLT)
```

Each refuses with an explanation rather than emitting a broken artifact when its
tooling is missing. Signing is opt-in through the environment (`SIGN_PFX`,
`INSTALLER_IDENTITY`, `NOTARY_PROFILE`); unsigned installers build, but
SmartScreen and Gatekeeper reject them on any machine that did not build them.

On the endpoint:

```bash
# Linux
dpkg -i glpi-osquery-agent_1.0.0_amd64.deb
glpi-osquery-agent install --server https://glpi.example.com \
    --secret <enrollment secret> --ca-cert /path/to/ca.pem
systemctl enable --now glpi-osquery-agent

# macOS — the tarball carries this script
sudo ./install.sh --server https://glpi.example.com --secret <enrollment secret>

# Windows — an MSI, for GPO, Intune, SCCM or any other deployment channel
msiexec /i glpi-osquery-agent_1.0.0_amd64.msi /qn ^
    SERVER=https://glpi.example.com ENROLLSECRET=<enrollment secret>

# Windows, one-off, from an elevated PowerShell — the zip carries this script
.\install.ps1 -Server https://glpi.example.com -Secret <enrollment secret>
```

MSI properties: `SERVER`, `ENROLLSECRET`, `CACERT`, `NOUPDATES=1` to pin the
host, and `INSTALLFOLDER`. Omit the credentials and the service is registered but
left stopped rather than restart-looping against a server it has never been told
about. Enrolment failing does not fail the install: the configuration is written
before GLPI is contacted, so an agent deployed during an outage enrols later.

The agent runs as a systemd unit, launchd daemon or Windows service. On Windows
it speaks the service control manager's start/stop handshake directly, so a
restart to complete an update is reported as a clean restart rather than a crash.
All three run as root/LocalSystem because osqueryd needs it to read SMBIOS,
disks, WMI and the registry.

With verbose MSI logging (`/l*v`) the enrollment secret can reach the log despite
being marked hidden. An enrollment secret is a shared, scopable, revocable
credential buying one thing — the right to obtain a per-agent node key — and
revoking it in GLPI kills it while already-enrolled agents keep working on their
own keys. If that is not acceptable, omit the properties and run
`glpi-osquery-agent install` separately.

The agent holds no collection logic. What a machine reports is decided by packs
served from GLPI; the agent owns the osqueryd lifecycle, the credentials and
updates.

## Features

**Self-update.** Publish a bundle's URL, SHA-256 and size under *Setup → osquery
Inventory → Agent updates*, then raise the rollout percentage. Agents verify the
checksum before installing, stage into a versioned directory, flip a symlink and
restart onto it. A version that starts but cannot reach the server never clears
its marker; one that cannot start at all is rolled back by `preflight.sh` after
three attempts, which lives outside the binary because a broken agent cannot
rescue itself.

**The device page.** GLPI's *Inventory information* card shows the agent's
version, useragent, contact address, last contact, a live **Agent status** and a
**Request inventory** button. The agent serves a small listener on port 62354 for
the last two, so GLPI queries the endpoint directly rather than the database.
That port answers only callers on the trusted list, published centrally under
*Setup → osquery Inventory* and refreshed on every check-in — trusting the
server's hostname alone is not enough when GLPI sits behind a TLS terminator or
is multi-homed.

**Monitors on Linux** come from `glpi-edid.ext`, an osquery extension in the
bundle exposing `/sys/class/drm/*/edid` as a `glpi_edid` table. GLPI's own import
rules drop monitors whose EDID carries no serial number; enable *Inventory →
Import monitor on partial serial number* for those.

**Your own extensions, without rebuilding the agent.** Register one under *Setup
→ osquery Inventory → osquery extensions*, publish the binary per platform and
architecture, and choose the entity it applies to. Agents install it into a
drop-in directory outside the versioned bundle, so a self-update does not remove
it. The manifest is the complete set an agent should have, so deactivating or
unscoping an extension uninstalls it.

The tables it registers are discovered from the endpoints — `osquery_registry`
joined to `pragma_table_info` — so they appear in the live-query console with
their real columns without anybody uploading a schema, and a pack query can be
gated on `requires_table`.

Publishing takes `plugin_glpiosquery_extension`, granted to nobody by default,
**and** a session that can see every entity. The right alone could be delegated
to an entity administrator, who could then push a root-executed binary to their
own machines.

**Ticket auto-evidence.** When an asset is attached to a ticket, the machine is
asked six triage questions — OS, uptime, disk, memory, top processes, active user
— and the answers are posted as one private followup.

A **Machine state** tab adds a *Capture now* button for a second reading. Where
an earlier capture exists the followup leads with what changed —
`msedge · rss_mb 1323.7 → 451.0 (-872.7)`. Rows sharing a name are summed rather
than paired, identifiers like PIDs are never subtracted, and probes whose values
are labels rather than measurements opt out.

Ships off; enable under *Setup → osquery Inventory*. A manual capture works
regardless. It collects a process list and the active user on every ticket, so it
is a thing to switch on knowingly. The followup is private by default. A machine
that never answers still gets a followup saying so, because silence in the
timeline is indistinguishable from the feature being off.

## Warranty lookups

Asks hardware vendors when each inventoried machine's warranty ends, and writes
the answer into **GLPI's own warranty fields** on the asset's *Financial
information* tab: `warranty_date`, `warranty_duration` and `warranty_info`.
Nothing is stored in a private format, so GLPI's warranty-expiry search option,
expiry-alert cron, dashboards and CSV export keep working unchanged.

**Setup → osquery Inventory → Warranty lookups.**

| Vendor | API | Credentials |
|---|---|---|
| Dell | TechDirect Asset Entitlements v5 | OAuth2 client ID + secret, from techdirect.dell.com |
| HP Inc. | Product Warranty API v2 | OAuth2 client ID + secret, from developers.hp.com |
| HPE | Support Entitlement (warrantyCheck) | OAuth2 client ID + secret, issued against a support agreement |
| Lenovo | Warranty & Contract v2.5 | A `ClientID` token from a Lenovo account representative |
| Apple | GSX REST v2 | AASP/self-servicing agreement, client certificate, Sold-To/Ship-To, activation token |
| Cisco | Support API SN2INFO v2 | OAuth2 client ID + secret, from apiconsole.cisco.com |
| Fortinet | FortiCare Registration API v3 | A FortiCloud **IAM API user**, not a portal login |
| Juniper | Service Asset API v1.0 (`css-asset`) | API key + application id + entity source id |
| Microsoft Surface | Surface API Management Service | Entra app in the Intune tenant + an API subscription key |
| Pure Storage | Pure1 REST API, support contracts | Pure1 application id + an RSA private key |

Every one needs an account with the vendor; none has an anonymous tier. Each is a
separate switch on top of a master switch, and nothing is contacted until both
are on. **Only the serial number leaves the server** — no hostname, user, entity
or instance URL. Requests go through GLPI's configured proxy.

Dell, Cisco and Juniper batch (100, 75 and 50 serials per call), so a
thousand-machine estate is a few dozen requests. Lookups run hourly from cron,
bounded per run, with a per-vendor interval floor. A vendor answering "wrong
credentials" or "slow down" is dropped for the rest of the run.

**Two of the ten answer about a fleet rather than a serial.** Microsoft and Pure
Storage publish no per-device endpoint, so the whole tenant or organisation is
fetched once per run:

- **Microsoft Surface** returns a CSV export of every Intune-enrolled Surface.
  The tenant must be enrolled for scanning first — a state change inside your
  Microsoft tenant, so it is a button on the settings page rather than something
  the cron does. The first scan takes up to five business days, and Microsoft
  refreshes biweekly, so "Check now" re-reads the same export.
- **Pure Storage matches on array name, not serial.** Pure1 publishes no serial
  number anywhere in its public API. An asset matches the Pure1 array whose name
  or FQDN equals its GLPI name, and the Warranty tab says so. Rename in one place
  and not the other and it shows as "not found" rather than a wrong date.

**Vendors deliberately absent**, each checked rather than assumed:

- **Arista Networks** — the only public API on `arista.com` is the software
  download service (`custom_data/api`, as used by eos-downloader); CloudVision
  describes devices under management, not support entitlement.
- **Ubiquiti** — `api.ui.com` and the UniFi APIs return device inventory with no
  coverage data; warranty runs through rma.ui.com, which wants proof of purchase.
- **Supermicro** — the serial warranty check is a web form; RMA is email.
- **Zebra, APC/Schneider, Acer, ASUS, MSI, Dynabook/Toshiba, Fujitsu** — a web
  form in every case.
- **Cisco Meraki** — excluded on purpose: Meraki serials are not in SN2INFO and
  would fail on every access point, every night.

Assets from any of those are recorded as *not applicable* rather than failing.

### What lands where

A machine routinely has several overlapping entitlements. Infocom holds one span,
so the **entitlement that ends last** is written; the full list is on the asset's
*Warranty* tab with the service level, when it was last checked, and why there is
no warranty when there is none. An empty Financial tab cannot distinguish "the
vendor has no record of this serial" from "the credentials expired a fortnight
ago".

Warranty fields typed in by hand are never overwritten unless an administrator
allows it, and the purchase date and supplier are only filled in when empty.

**GLPI computes the expiry two different ways**, which looks like an off-by-one
here and is not. The search option and the warranty-alert cron both use
`DATE_ADD(warranty_date, INTERVAL warranty_duration MONTH)` and land exactly on
the vendor's end date; the Financial tab subtracts a day to show the last covered
day. The vendor's exact date is always in `warranty_info`.

The engine is shared with `glpinetscan`, which does the same job for the
switches, printers and UPSs its SNMP scanner finds. Both ship a complete copy so
neither requires the other; in the monorepo `tools/sync-warranty.sh` projects one
into the other, and everything per-plugin lives in `Warranty/Scope.php`.

No glpi-ai tool is added for this: the data is in GLPI's native fields, which the
assistant already reads.

## glpi-ai tools

| Tool | What it does |
|---|---|
| `osquery_agents` | Find machines with an agent, their platform and when last seen |
| `osquery_tables` | The tables and columns available on a platform |
| `osquery_live` | Run a read-only query on named machines and return the rows |

Nothing here grants anything a technician did not already have. The rights are
the console's own — `osquery_live` needs `plugin_glpiosquery_rawsql` at UPDATE,
which this plugin grants to nobody by default. Every call lands in glpi-ai's tool
log under the caller's name.

- **Only SELECT**, one statement, through the same rejector the console uses. A
  refusal comes back as the tool's result with the reason.
- **Agent ids are resolved through the entity restriction in SQL**, so an agent
  in another entity's entity cannot be reached by guessing its number.
- **Silence is reported.** A campaign is asynchronous, so the tool waits a
  bounded time and then says how many machines did not answer.

## Tests

```bash
docker exec glpi-glpi-1 php /var/www/glpi/plugins/glpiosquery/tests/run-tests.php
docker exec glpi-glpi-1 php /var/www/glpi/plugins/glpiosquery/tests/warranty.php
cd agent && go test ./...
```

67 dependency-free unit tests cover the EDID decoder, every osquery→GLPI unit
conversion, the schema's enum and date constraints, the live-query SQL guard and
the update rollout rings. 370 more cover the warranty lookup: all ten vendor
clients against captured response shapes, asserting the requests as well since
none of these APIs can be called from a test environment, plus vendor detection,
failure classification and the projection onto GLPI's fields.

Browser checks (console, autocomplete, per-computer tab, settings) are in
`plugin/tests/browser/`.

## Status

All nine phases are built. Verified end to end against a real `osqueryd` and real
hardware (a Framework Laptop 13 on Ubuntu 26.04 reporting its CPU, both DIMMs, an
NVMe disk, 2175 packages, 17 NICs and both monitors): enrollment,
platform-filtered pack delivery, snapshot ingest, inventory assembly into a
native GLPI Computer, live queries with a Monaco-based console fleet-wide and
per-device with schema-aware autocomplete, Windows/Linux platform backfill, the
Linux EDID extension, the agent management UI, the saved-query library,
compliance reporting, and the agent itself including a verified self-update and
rollback.

Not verified locally: the `.pkg` installer, and the macOS and Windows agents on
their own operating systems — they cross-compile and their bundles are built and
inspected, but no Windows or macOS machine was available. The MSI is built
locally on Linux by `packaging/build-msi.sh` using wixl from GNOME's msitools,
which also asserts the package contents; the `windows-msi` workflow then installs
and uninstalls it on a Windows runner and checks the service resolves through the
`current` junction rather than a versioned path.

## Licence

Two components, two licences.

- `plugin/` — GPL-3.0-or-later. A GLPI plugin loaded into GLPI's process and
  extending its classes, so a derivative work.
- `agent/` — MIT. A standalone program that reaches the plugin over HTTPS and
  contains no GLPI code.
