# GLPI osquery Inventory

A replacement for GLPI's native Inventory and the GLPI Agent, built on
[osquery](https://osquery.io) — with **live queries** across the fleet.

Two deliverables:

| Path | What |
|---|---|
| `plugin/` | The GLPI 11 plugin (`glpiosquery`). Speaks osquery's TLS remote API, assembles inventory, runs live queries. |
| `agent/` | The endpoint agent (Go): supervises a bundled `osqueryd`, self-updates, and ships the Linux EDID extension. |
| `testdata/protocol/` | Real request captures used as fixtures. |

## How it works

The thing running on the endpoint is a **stock `osqueryd`** — the plugin implements
osquery's own enroll / config / log / distributed endpoints, so any osquery build can point
at GLPI. Scheduled snapshot results are assembled server-side into a GLPI-native inventory
document and handed to `Glpi\Inventory\Inventory`, which means assets land as ordinary
Computers with the import rules engine, entity rules and refused-equipment handling all
applied. Live queries ride osquery's `distributed` plugin.

```
stock osqueryd ──HTTPS──▶ glpiosquery ──▶ Glpi\Inventory\Inventory ──▶ Computer, Software,
                                                                       NetworkPort, Volume…
```

## Requirements

**GLPI must be served over HTTPS.** osquery 5.x refuses plain HTTP and no longer has a
`--tls_allow_unsafe` escape hatch. Self-signed or internal-CA setups must ship the CA to the
endpoint (the installers do this).

## Development

You need a GLPI with this plugin installed, reachable over **TLS** — osquery
will not enroll over plain HTTP — and a host running stock `osqueryd` to point
at it. Any GLPI works; the pieces that matter are:

```bash
# a CA and server certificate osquery will accept, and a TLS front for GLPI
#   (osquery pins the CA; a self-signed server cert is fine)
# then, in the GLPI container:
php bin/console glpi:plugin:install glpiosquery -u glpi
php bin/console glpi:plugin:activate glpiosquery
```

Create an enrollment secret in **Setup → osquery Inventory**, then point the test host at it:

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

The shipped packs collect on 1-hour and 24-hour intervals, so nothing lands within a short
test run — shorten `query_interval` in `glpi_plugin_glpiosquery_queries` while iterating.
Inventory assembly is a cron task (`osqueryInventory`, every 60 s) and waits for an agent's
snapshots to settle for 30 s before building a document.

## The agent

```bash
cd agent
./build.sh 1.0.0 all      # bundles for all six targets: linux/darwin/windows x amd64/arm64
./build.sh 1.0.0 linux/amd64
```

A bundle is one archive holding the supervisor, the pinned `osqueryd` and — on Linux — the
EDID extension. Keeping them in a single versioned artifact is what makes self-update
atomic: `current` points at one directory of binaries that were tested together.

Native installers wrap that same archive, so what an installer lays down is byte-identical
to what a self-update fetches:

```bash
./packaging/build-deb.sh 1.0.0 amd64        # .deb           (needs dpkg-deb)
./packaging/build-msi.sh 1.0.0 amd64        # .msi           (needs wixl + msitools)
./packaging/build-msi.sh 1.0.0 arm64        # .msi, Windows on ARM
./packaging/build-pkg.sh 1.0.0 universal    # .pkg           (needs macOS + Xcode CLT)
```

Each refuses with an explanation rather than emitting a broken artifact when its tooling is
missing. Signing is opt-in through the environment (`SIGN_PFX`, `INSTALLER_IDENTITY`,
`NOTARY_PROFILE`); unsigned installers build, but SmartScreen and Gatekeeper will reject
them on any machine that did not build them.

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

MSI properties: `SERVER`, `ENROLLSECRET`, `CACERT`, `NOUPDATES=1` to pin the host, and
`INSTALLFOLDER`. Omit the credentials and the service is registered but left stopped rather
than restart-looping against a server it has never been told about; enrolment failing does
not fail the install, because the configuration is written before GLPI is contacted, so an
agent deployed during an outage enrols itself later.

The agent runs as a systemd unit, a launchd daemon or a Windows service respectively; on
Windows it speaks the service control manager's start/stop handshake directly, so a restart
to complete an update is reported as a clean restart rather than a crash. All three run as
root/LocalSystem because osqueryd needs it to read SMBIOS, disks, WMI and the registry.

Enrolment can be done at install time or separately. The trade-off is worth knowing: with
verbose logging (`/l*v`) the secret can reach the MSI log despite being marked hidden. That
is acceptable because of what an enrollment secret is — a shared, scopable, revocable
credential that buys exactly one thing, the right to obtain a per-agent node key. Revoke it
in GLPI and it is dead, while agents that already enrolled keep working on their own keys.
If that is not acceptable in your environment, omit the properties and run
`glpi-osquery-agent install` separately.

The agent holds **no collection logic** — what a machine reports is decided by packs served
from GLPI. It owns the osqueryd lifecycle, the credentials, and updates.

**Self-update.** Publish a bundle's URL, SHA-256 and size under *Setup → osquery Inventory →
Agent updates*, then raise the rollout percentage. Agents verify the checksum before
installing, stage into a versioned directory, flip a symlink and restart onto it. A version
that starts but cannot reach the server never clears its marker; one that cannot start at
all is rolled back by `preflight.sh` after three attempts — that guard lives outside the
binary precisely because a broken agent cannot rescue itself.

**The device page.** GLPI's *Inventory information* card shows the agent's version,
useragent, contact address, last contact, a live **Agent status** and a **Request
inventory** button. The agent serves a small listener on port 62354 for the last two — GLPI
queries the endpoint directly rather than the database. That port only answers callers on
the trusted list, which is published centrally under *Setup → osquery Inventory* and
refreshed on every check-in: trusting only the server's hostname is not enough, because
GLPI sits behind a TLS terminator and may be multi-homed, so the request usually arrives
from a different address than the agent was given.

**Monitors on Linux** come from `glpi-edid.ext`, an osquery extension in the bundle exposing
`/sys/class/drm/*/edid` as a `glpi_edid` table. Note that GLPI's own import rules drop
monitors whose EDID carries no serial number; enable *Inventory → Import monitor on partial
serial number* if you want those.

**Your own extensions, without rebuilding the agent.** An osquery extension is a standalone
executable, so there is no reason a site-specific table should mean a new agent release.
Register one under *Setup → osquery Inventory → osquery extensions*, publish the binary per
platform and architecture, and choose the entity it applies to; agents install it into a
drop-in directory outside the versioned bundle, so a self-update does not remove it. The
manifest is the complete set an agent should have, so deactivating or unscoping an extension
uninstalls it rather than merely ceasing to offer it.

The tables it registers are then **discovered from the endpoints** — `osquery_registry` joined
to `pragma_table_info` — so they appear in the live-query console with their real columns
without anybody uploading a schema, and a pack query can be gated on `requires_table` so it is
only sent to machines that can actually answer it.

Publishing takes the `plugin_glpiosquery_extension` right, which is granted to nobody by
default, **and** a session that can see every entity. That second condition is the point: the
right on its own could be delegated to an entity administrator, who could then push a
root-executed binary to their own machines. An extension can be scoped to an entity; only an
administrator of the whole instance decides that it is.

**Ticket auto-evidence.** When an asset is attached to a ticket, the machine is asked six
triage questions — OS, uptime, disk, memory, top processes, active user — and the answers are
posted as a single private followup on the ticket timeline. It answers the questions a
technician would otherwise have to ask the user, before anyone has read the ticket.

A **Machine state** tab on the ticket adds a *Capture now* button for a second reading after
the technician has done something. When an earlier capture exists the followup leads with what
changed — `msedge · rss_mb 1323.7 → 451.0 (-872.7)` — so a fix is shown rather than asserted.
Rows sharing a name are summed rather than paired, identifiers like PIDs are never subtracted,
and probes whose values are labels rather than measurements opt out.

Ships **off**; enable under *Setup → osquery Inventory*. A manual capture works regardless,
since pressing a button on a ticket is a clearer instruction than a global default. It collects a process list and the
active user on every ticket, which is a thing to switch on knowingly. The followup is private
by default — a process list is for the technician, not the requester. A machine that never
answers still gets a followup saying so, because silence in the timeline is indistinguishable
from the feature being switched off.

## Warranty lookups

The plugin can ask hardware vendors when each inventoried machine's warranty ends, and write
the answer into **GLPI's own warranty fields** on the asset's *Financial information* tab —
`warranty_date`, `warranty_duration` and `warranty_info`. Nothing is stored in a private
format, so GLPI's existing warranty-expiry search option, its expiry-alert cron, the
dashboards and CSV export all keep working with no further help.

Setup → osquery Inventory → **Warranty lookups**.

| Vendor | API | Credentials |
|---|---|---|
| Dell | TechDirect Asset Entitlements v5 | OAuth2 client ID + secret, from techdirect.dell.com |
| HP Inc. | Product Warranty API v2 | OAuth2 client ID + secret, from developers.hp.com |
| HPE | Support Entitlement (warrantyCheck) | OAuth2 client ID + secret, issued against a support agreement |
| Lenovo | Warranty & Contract v2.5 | A `ClientID` token from a Lenovo account representative |
| Apple | GSX REST v2 | AASP/self-servicing agreement, client certificate, Sold-To/Ship-To, activation token |
| Cisco | Support API SN2INFO v2 | OAuth2 client ID + secret, from apiconsole.cisco.com |
| Fortinet | FortiCare Registration API v3 | A FortiCloud **IAM API user** (not a portal login) |
| Juniper | Service Asset API v1.0 (`css-asset`) | API key + application id + customer source id, from Juniper onboarding |
| Microsoft Surface | Surface API Management Service | Entra app in the Intune tenant + an API subscription key |
| Pure Storage | Pure1 REST API, support contracts | Pure1 application id + an RSA private key |

Every one of these requires an account with the vendor; none has an anonymous tier. Each is
a separate switch on top of a master switch, and nothing is contacted until both are on.
**Only the serial number leaves the server** — no hostname, no user, no entity, no instance
URL. Requests go through GLPI's configured proxy.

Dell, Cisco and Juniper batch (100, 75 and 50 serials per call), so a thousand-machine
estate is a few dozen requests. Lookups run hourly from cron, bounded per run, with a
per-vendor interval floor; a vendor that answers "wrong credentials" or "slow down" is
dropped for the rest of the run rather than asked another ninety times.

**Two of the ten answer about a fleet rather than a serial.** Microsoft and Pure Storage
publish no per-device endpoint, so the whole tenant or organisation is fetched once per run
and every asset is answered from that snapshot:

- **Microsoft Surface** returns a CSV export of every Intune-enrolled Surface. The tenant
  must be *enrolled for scanning* first — a state change inside your Microsoft tenant, so it
  is a button on the settings page rather than something the cron does on its own, and the
  first scan takes up to five business days. Microsoft refreshes the data biweekly, so
  "Check now" re-reads the same export.
- **Pure Storage matches on array name, not serial** — Pure1 publishes no serial number
  anywhere in its public API. An asset is matched to the Pure1 array whose name or FQDN
  equals its GLPI name, and the Warranty tab says so. Rename an array in one place and not
  the other and it stops matching, which shows up as "not found" rather than a wrong date.

**Vendors deliberately absent**, because they have no serial-number warranty API a plugin
can call. Each was checked, not assumed:

- **Arista Networks** — the only public API on `arista.com` is the software download service
  (`custom_data/api`, as used by eos-downloader); CloudVision's APIs describe devices under
  management, not support entitlement. Warranty is the support portal's serial page.
- **Ubiquiti** — `api.ui.com` and the UniFi APIs return device inventory with no coverage
  data; warranty runs through the RMA form at rma.ui.com, which wants proof of purchase
  rather than a serial.
- **Supermicro** — the serial-number warranty check is a web form; RMA is email.
- **Zebra, APC/Schneider, Acer, ASUS, MSI, Dynabook/Toshiba, Fujitsu** — a web form in every
  case. Scraping one would break silently and is not shipped here.
- **Cisco Meraki** — excluded on purpose: Meraki serials are not in SN2INFO and would fail
  on every access point, every night.

Assets from any of those are recorded as *not applicable* rather than failing.

### What lands where

A machine routinely has several overlapping entitlements — a base warranty, a ProSupport or
Care Pack extension, sometimes accidental-damage cover with its own clock. Infocom holds one
span, so the **entitlement that ends last** is the one written; the full list is on the
asset's *Warranty* tab, along with the service level, when it was last checked, and — the
case that actually generates support questions — *why* there is no warranty. An empty
Financial tab cannot tell "the vendor has no record of this serial" from "the credentials
expired a fortnight ago", and those have very different answers.

Warranty fields somebody typed in by hand are never overwritten unless an administrator
explicitly allows it, and the purchase date and supplier are only ever filled in when empty.

One GLPI quirk worth knowing, because it looks like an off-by-one here and is not:
**GLPI computes the expiry two different ways.** The search option and the warranty-alert
cron both use `DATE_ADD(warranty_date, INTERVAL warranty_duration MONTH)`, which lands
exactly on the vendor's end date; the Financial tab subtracts a day, to show the last day
still covered. The vendor's exact date is always in `warranty_info`.

The engine is shared with [glpi-netscan](https://github.com/bijstaan/glpi-netscan), which
does the same job for the switches, printers and UPSs its SNMP scanner finds. Both ship a
complete copy so neither requires the other; in the monorepo `tools/sync-warranty.sh`
projects one into the other, and everything genuinely per-plugin lives in
`Warranty/Scope.php`.

No glpi-ai tool is added for this on purpose: the data is in GLPI's native fields, which the
assistant already reads, and a second source could only disagree with the first.

## Tests

```bash
docker exec glpi-glpi-1 php /var/www/glpi/plugins/glpiosquery/tests/run-tests.php
docker exec glpi-glpi-1 php /var/www/glpi/plugins/glpiosquery/tests/warranty.php
```

67 dependency-free unit tests covering the EDID decoder, every osquery→GLPI unit
conversion, the schema's enum/date constraints, the live-query SQL guard and the update
rollout rings, plus 370 for the warranty lookup — all ten vendor clients against captured
response shapes (asserting the *requests* too, since none of these APIs can be called from a
test environment), vendor detection, failure classification and the projection onto GLPI's
fields. Browser checks (console, autocomplete, per-computer tab, settings) live in
`tests/browser/`.

```bash
cd agent && go test ./...
```

## Status

All nine phases are built. Verified end to end against a real `osqueryd`, and against real
hardware (a Framework Laptop 13 running Ubuntu 26.04, reporting its CPU, both DIMMs, an NVMe
disk, 2175 packages, 17 NICs and both monitors): enrollment, platform-filtered pack
delivery, snapshot ingest, inventory assembly into a native GLPI Computer, live queries with
a Monaco-based console (fleet-wide and per-device, with schema-aware autocomplete),
Windows/Linux platform backfill, the Linux EDID extension, the agent management UI, the
saved-query library, compliance reporting, and the agent itself — including a verified
self-update and a verified rollback.

Not verified locally: the `.pkg` installer, and the macOS and Windows agents on their own
operating systems — they cross-compile and their bundles are built and inspected, but no
Windows or macOS machine was available here. The MSI itself *is* built locally: it is
produced on Linux by `packaging/build-msi.sh` using wixl from GNOME's msitools, which also
asserts the package's contents. The `windows-msi` workflow then installs and uninstalls it
on a Windows runner and checks the service resolves through the `current` junction rather
than a versioned path.

---

## Asking osquery from glpi-ai's assistant

If **glpi-ai** is installed, this plugin registers three tools with it, so a
technician can ask the troubleshooting panel a question and have it look at the
endpoint rather than guess:

| Tool | What it does |
|---|---|
| `osquery_agents` | find machines with an agent, their platform and when last seen |
| `osquery_tables` | the tables and columns available on a platform |
| `osquery_live` | run a read-only query on named machines and return the rows |

**Nothing here grants anything a technician did not already have.** The rights
are the console's own — `osquery_live` needs `plugin_glpiosquery_rawsql` at
UPDATE, which this plugin grants to nobody by default. Somebody who cannot type
a query into the console cannot have the assistant type one either, and every
call lands in glpi-ai's tool log under their own name.

Three more things the tool does that the console does for a human:

- **Only SELECT**, one statement, through the same rejector the console uses. A
  refusal comes back as the tool's result with the reason, which the model reads
  and corrects from.
- **Agent ids are resolved through the entity restriction in SQL**, so an agent
  in another customer's entity cannot be reached by guessing its number.
- **Silence is reported.** A campaign is asynchronous, so the tool waits a
  bounded time and then says how many machines did not answer — because a model
  told "no machine has that file" when three never replied will conclude the
  file is gone.

Without glpi-ai none of this exists; the hook is only ever read by that plugin.

## Install

```bash
# from the GLPI root — the directory has to be named for the plugin
# key, which is not the repository name
git clone https://github.com/bijstaan/glpi-osquery.git plugins/glpiosquery
php bin/console plugin:install -u glpi glpiosquery
php bin/console plugin:activate glpiosquery
```

## Licence

Two components, two licences.

- `plugin/` — GNU General Public License, version 3 or later. It is a GLPI
  plugin, loaded into GLPI's process and extending its classes, so it is a
  derivative work of GLPI and carries GLPI's licence.
- `agent/` — MIT. It is a standalone program that reaches the plugin over
  HTTPS and contains no GLPI code.
