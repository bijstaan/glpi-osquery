<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CronTask;
use Glpi\Inventory\Inventory;
use GlpiPlugin\Glpiosquery\Inventory\Assembler;

/**
 * Turns collected snapshots into GLPI assets.
 *
 * Assembly is deliberately *not* done inline on the /log request. osquery
 * flushes results in batches on its own timer, so one collection cycle can
 * arrive spread over several POSTs; building an inventory the moment the first
 * batch lands would publish an asset missing whatever had not arrived yet, and
 * then immediately republish it. Instead /log only sets a dirty flag, and this
 * runs from cron over agents whose snapshots have stopped moving — one
 * inventory per cycle, complete.
 */
final class InventorySync
{
    /** An agent is assembled once its newest snapshot is this many seconds old. */
    public const SETTLE_SECONDS = 30;

    /**
     * Assemble anyway once an agent has been waiting this long.
     *
     * The settle window assumes result batches arrive in bursts with quiet
     * gaps. That holds for the shipped hourly packs, but any query whose
     * interval is shorter than the settle window keeps the agent permanently
     * "still arriving" and its inventory would never be built at all — the
     * asset would simply stop updating, with nothing logged to say why.
     * This bound guarantees progress regardless of how the packs are tuned.
     */
    public const FORCE_AFTER_SECONDS = 900;

    /**
     * Assemble and submit every settled dirty agent.
     *
     * @return int number of agents inventoried
     */
    public static function runDirty(int $limit = 100): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $cutoff = date('Y-m-d H:i:s', time() - self::SETTLE_SECONDS);
        $done   = 0;

        $candidates = [];
        foreach (
            $DB->request([
                'SELECT' => ['id', 'last_inventory_at'],
                'FROM'   => Node::TABLE,
                'WHERE'  => [
                    'inventory_dirty' => 1,
                    'is_deleted'      => 0,
                    'is_active'       => 1,
                ],
                'LIMIT'  => $limit,
            ]) as $row
        ) {
            $candidates[(int) $row['id']] = $row['last_inventory_at'];
        }

        $force_before = date('Y-m-d H:i:s', time() - self::FORCE_AFTER_SECONDS);

        foreach ($candidates as $agents_id => $last_inventory_at) {
            // Overdue agents are assembled whether or not they look settled.
            $overdue = $last_inventory_at === null || $last_inventory_at < $force_before;
            // Skip agents still receiving this cycle's batches.
            $newest = null;
            foreach (
                $DB->request([
                    'SELECT' => [new \QueryExpression('MAX(' . $DB->quoteName('date_mod') . ') AS ' . $DB->quoteName('newest'))],
                    'FROM'   => ResultIngest::SNAPSHOT_TABLE,
                    'WHERE'  => ['plugin_glpiosquery_agents_id' => $agents_id],
                ]) as $row
            ) {
                $newest = $row['newest'];
            }

            if ($newest === null) {
                continue;
            }

            if ($newest > $cutoff && !$overdue) {
                continue;
            }

            if (self::runAgent($agents_id)) {
                $done++;
            }
        }

        return $done;
    }

    /** Assemble and submit one agent. Returns true when GLPI accepted it. */
    public static function runAgent(int $agents_id): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $agent = null;
        foreach ($DB->request(['FROM' => Node::TABLE, 'WHERE' => ['id' => $agents_id], 'LIMIT' => 1]) as $row) {
            $agent = $row;
        }
        if ($agent === null) {
            return false;
        }

        $document = Assembler::forAgent($agent);
        if ($document === null) {
            // Nothing usable yet (no anchor query). Clear the flag so we do not
            // spin on it every cron run; the next result batch sets it again.
            Node::touch($agents_id, ['inventory_dirty' => 0]);
            return false;
        }

        try {
            $inventory = new Inventory();
            // setData re-encodes what it is given, and the schema validator
            // wants objects rather than associative arrays.
            $inventory->setData(json_decode((string) json_encode($document)));

            if ($inventory->inError()) {
                self::logErrors($agents_id, $inventory->getErrors());
                return false;
            }

            $inventory->doInventory();

            if ($inventory->inError()) {
                self::logErrors($agents_id, $inventory->getErrors());
                return false;
            }

            $fields = [
                'inventory_dirty'   => 0,
                'last_inventory_at' => date('Y-m-d H:i:s'),
            ];

            // Remember which asset this agent produced, so the UI can link an
            // agent to its Computer and vice versa.
            $item = $inventory->getItem();
            if ($item instanceof \CommonDBTM && !$item->isNewItem()) {
                $fields['itemtype'] = $item->getType();
                $fields['items_id'] = (int) $item->getID();
            }

            if ($item instanceof \CommonDBTM && !$item->isNewItem()) {
                self::refreshPortMetrics($item, $document);
            }

            $glpi_agent = $inventory->getAgent();
            if ($glpi_agent instanceof \CommonDBTM && !$glpi_agent->isNewItem()) {
                $fields['agents_id'] = (int) $glpi_agent->getID();
                self::describeAgent($glpi_agent, $agent);
            }

            Node::touch($agents_id, $fields);

            return true;
        } catch (\Throwable $e) {
            self::logErrors($agents_id, [$e->getMessage()]);
            return false;
        }
    }

    /**
     * Push interface traffic counters onto the imported network ports.
     *
     * The two graphs on a port's Statistics tab are drawn from
     * glpi_networkportmetrics, one row per port per day, and GLPI writes that
     * row in NetworkPort::updateMetrics() from the port's own ifinbytes /
     * ifoutbytes / ifinerrors / ifouterrors columns whenever the port is added
     * or updated.
     *
     * Sending the counters in the inventory document only covers the first
     * half of that. Computers reach network ports through Asset\NetworkCard,
     * whose InventoryNetworkPort trait restricts its update to
     * logical_number, ifstatus, ifinternalstatus, ifalias and is_dynamic, and
     * leaves the portUpdated() hook empty — only Asset\NetworkPort, the SNMP
     * network-equipment path, overrides it to write metrics. So an endpoint's
     * counters would be captured once, when the port was first created, and
     * never move again: a flat line for the life of the machine.
     *
     * Writing them here restores the missing half with the same call core
     * makes for a switch. History is suppressed because these change on every
     * cycle by design, and a fleet of laptops with a dozen interfaces each
     * would otherwise bury every real change in the log.
     */
    private static function refreshPortMetrics(\CommonDBTM $item, array $document): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $counters = [];
        foreach ($document['content']['networks'] ?? [] as $nic) {
            if (!isset($nic['ifinbytes'])) {
                continue;
            }

            // The document carries one entry per address, so an interface with
            // several IPs repeats here; they all describe the same port and
            // carry the same counters, so the last one simply wins.
            $counters[self::portKey((string) ($nic['description'] ?? ''), (string) ($nic['mac'] ?? ''))] = [
                'ifinbytes'   => (int) $nic['ifinbytes'],
                'ifoutbytes'  => (int) ($nic['ifoutbytes'] ?? 0),
                'ifinerrors'  => (int) ($nic['ifinerrors'] ?? 0),
                'ifouterrors' => (int) ($nic['ifouterrors'] ?? 0),
            ];
        }

        if ($counters === []) {
            return;
        }

        $port = new \NetworkPort();
        foreach (
            $DB->request([
                'SELECT' => ['id', 'name', 'mac'],
                'FROM'   => 'glpi_networkports',
                'WHERE'  => [
                    'itemtype'   => $item->getType(),
                    'items_id'   => (int) $item->getID(),
                    'is_deleted' => 0,
                ],
            ]) as $row
        ) {
            $key = self::portKey((string) ($row['name'] ?? ''), (string) ($row['mac'] ?? ''));
            if (!isset($counters[$key])) {
                continue;
            }

            $port->update($counters[$key] + [
                'id'          => (int) $row['id'],
                '_no_history' => true,
            ]);
        }
    }

    /** Match ports the way GLPI's own importer does: name and MAC, case-folded. */
    private static function portKey(string $name, string $mac): string
    {
        return strtolower(trim($name)) . '|' . strtolower(trim($mac));
    }

    /**
     * Fill in the agent facts GLPI can only learn from an HTTP request.
     *
     * GLPI populates `useragent` and `remote_addr` from `$_SERVER` while
     * handling an inventory POST, and the `use_module_*` capability flags from
     * an `enabled-tasks` key it only reads on the CONTACT/prolog request. None
     * of that reaches us: the inventory document is assembled here, in cron,
     * from results osquery delivered earlier — there is no live HTTP request to
     * read, and the document schema forbids extra root keys, so `enabled-tasks`
     * cannot travel with it either.
     *
     * The result is a device page showing an agent with no version, no address
     * and every capability switched off. So the record is completed directly
     * from what we actually know about the endpoint.
     */
    private static function describeAgent(\CommonDBTM $glpi_agent, array $agent): void
    {
        $version = trim((string) ($agent['agent_version'] ?? ''));

        $input = [
            'id'        => (int) $glpi_agent->getID(),
            'useragent' => 'glpi-osquery-agent/' . ($version !== '' ? $version : PLUGIN_GLPIOSQUERY_VERSION)
                         . ' (osquery ' . (string) ($agent['osquery_version'] ?? '?') . ')',

            // Declared honestly: this agent performs computer inventory and
            // nothing else. Claiming deployment or network discovery would put
            // buttons in front of an operator that quietly do nothing.
            'use_module_computer_inventory'   => 1,
            'use_module_network_discovery'    => 0,
            'use_module_network_inventory'    => 0,
            'use_module_remote_inventory'     => 0,
            'use_module_wake_on_lan'          => 0,
            'use_module_esx_remote_inventory' => 0,
            'use_module_package_deployment'   => 0,
            'use_module_collect_data'         => 0,
        ];

        // The address the endpoint actually contacts us from, captured on its
        // osquery check-ins rather than guessed from the asset's interfaces.
        $remote = trim((string) ($agent['remote_addr'] ?? ''));
        if ($remote !== '') {
            $input['remote_addr'] = $remote;
        }

        $port = (int) ($agent['listen_port'] ?? 0);
        if ($port > 0) {
            $input['port'] = $port;
        }

        $glpi_agent->update($input);
    }

    /**
     * Keep GLPI's `last_contact` in step with what the fleet is actually doing.
     *
     * GLPI stamps last_contact only when an inventory is submitted, which for
     * this plugin is hourly at best. An agent checking in every ten seconds
     * would therefore be displayed as last seen an hour ago — indistinguishable
     * on the device page from one that has genuinely gone away, which is the
     * single most important thing that field is used to judge.
     *
     * @return int rows updated
     */
    public static function syncLastContact(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->doQuery(
            'UPDATE ' . $DB->quoteName('glpi_agents') . ' a
             INNER JOIN ' . $DB->quoteName(Node::TABLE) . ' o ON o.' . $DB->quoteName('agents_id') . ' = a.' . $DB->quoteName('id') . '
             SET a.' . $DB->quoteName('last_contact') . ' = o.' . $DB->quoteName('last_seen') . '
             WHERE o.' . $DB->quoteName('last_seen') . ' IS NOT NULL
               AND (a.' . $DB->quoteName('last_contact') . ' IS NULL
                    OR a.' . $DB->quoteName('last_contact') . ' < o.' . $DB->quoteName('last_seen') . ')'
        );

        return $DB->affectedRows();
    }

    /**
     * Record a failed inventory against the agent.
     *
     * These land in the agent's status log rather than only in GLPI's global
     * error log, because "this machine has not inventoried since Tuesday" is a
     * question asked about one agent, not about the server.
     */
    private static function logErrors(int $agents_id, array $errors): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $message = 'inventory failed: ' . mb_substr(implode(' | ', array_map('strval', $errors)), 0, 2000);

        $DB->insert(ResultIngest::STATUS_TABLE, [
            'plugin_glpiosquery_agents_id' => $agents_id,
            'severity'  => 2,
            'filename'  => 'InventorySync',
            'line'      => 0,
            'message'   => $message,
            'logged_at' => date('Y-m-d H:i:s'),
        ]);

        // Leave inventory_dirty set: the next cron run retries, which is right
        // for a transient failure and harmless for a permanent one beyond the
        // log line above.
        trigger_error('glpiosquery: ' . $message, E_USER_WARNING);
    }

    // ------------------------------------------------------------------- cron

    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'osqueryInventory' => ['description' => __('Assemble osquery results into GLPI assets', 'glpiosquery')],
            'osqueryMaintenance' => ['description' => __('Expire osquery live queries and prune status logs', 'glpiosquery')],
            default => [],
        };
    }

    /** Cron: assemble settled dirty agents, and keep last_contact current. */
    public static function cronOsqueryInventory(CronTask $task): int
    {
        $count = self::runDirty();

        // Runs every cycle, not only when something was inventoried: liveness
        // is exactly what needs refreshing on the quiet agents.
        self::syncLastContact();

        // On the 60-second cycle rather than the 5-minute housekeeping one:
        // evidence is only useful while the technician still has the ticket
        // open, and probes typically answer within one distributed interval.
        $count += TicketEvidence::renderPending();

        $task->addVolume($count);

        return $count > 0 ? 1 : 0;
    }

    /** Cron: housekeeping — expire stale campaigns, prune status logs. */
    public static function cronOsqueryMaintenance(CronTask $task): int
    {
        $volume = Campaign::expire()
                + Campaign::purgeOld()
                + Campaign::purgeOrphans()
                + ResultIngest::pruneStatus()
                + Compliance::raiseTickets();
        $task->addVolume($volume);

        return $volume > 0 ? 1 : 0;
    }
}
