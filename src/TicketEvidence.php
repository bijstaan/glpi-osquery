<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;
use ITILFollowup;
use Ticket;

/**
 * Triage evidence captured from the machine a ticket is about.
 *
 * The first thing a technician does with a new ticket is ask the questions the
 * endpoint could have answered before anyone read it: is it even on, how long
 * has it been up, is the disk full, what is eating the memory, who is logged
 * in. Each of those is a round trip to a user who is already annoyed, and the
 * answers are stale by the time they arrive.
 *
 * So they are collected once, at the moment an asset is attached to a ticket,
 * and written into the timeline as a single followup.
 *
 * Deliberately **off by default**: this captures a process list and the logged
 * in user without anyone asking, on every ticket. That is a reasonable thing
 * to switch on knowingly and not a reasonable thing to start doing
 * on an upgrade. The followup is private for the same reason — a process list
 * is for the technician, not for the requester.
 */
final class TicketEvidence
{
    public const TABLE = 'glpi_plugin_glpiosquery_evidences';

    /**
     * Columns that are names for things rather than measurements of them.
     *
     * A PID is the clearest case: subtracting one from another produces a
     * number, and that number means nothing at all. Left in, the comparison
     * confidently reports "msedge · pid -494" next to real findings, which
     * teaches a technician to distrust the whole table.
     */
    private const IDENTIFIER_COLUMNS = ['pid', 'ppid', 'uid', 'gid', 'euid', 'egid', 'port'];

    public const LINKED = 'link';
    public const MANUAL = 'manual';

    public const PENDING  = 'pending';
    public const RENDERED = 'rendered';
    public const SKIPPED  = 'skipped';

    /**
     * How long to wait for an agent before writing up what did arrive.
     *
     * Past this the followup is written anyway, saying plainly which probes
     * went unanswered. A ticket that silently never gets its evidence is worse
     * than one that says the machine did not answer — the second tells the
     * technician something true about the machine.
     */
    public const COLLECT_SECONDS = 180;

    /**
     * Don't re-capture for the same ticket and asset inside this window.
     *
     * Assets get detached and reattached, and tickets get edited; without this
     * a fiddly morning produces a timeline of near-identical followups.
     */
    public const DEDUPE_SECONDS = 3600;

    public static function enabled(): bool
    {
        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);

        return !empty($settings['ticket_evidence']);
    }

    public static function followupIsPrivate(): bool
    {
        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);

        // Private unless explicitly turned off: the default has to be the
        // careful one, because the alternative shows a requester the process
        // list of their own machine.
        return !isset($settings['ticket_evidence_private'])
            || !empty($settings['ticket_evidence_private']);
    }

    /**
     * The triage probes, in the order they appear in the followup.
     *
     * Ordered as a technician reads them: what is it, how long has it been up,
     * is it full, what is it running, who is on it. Six probes go out in a
     * single distributed read, because dispatchFor batches everything an agent
     * is owed into one response.
     *
     * @return array<int,array{key:string,label:string,sql:array<string,string>}>
     */
    public static function probes(): array
    {
        return [
            [
                'key'   => 'os',
                'label' => __('Operating system', 'glpiosquery'),
                'sql'   => ['all' => 'SELECT name, version, build, arch FROM os_version;'],
                // Nothing here is a quantity; an OS upgrade is news, but not
                // news expressible as a plus or minus.
                'compare' => false,
            ],
            [
                'key'   => 'uptime',
                'label' => __('Uptime', 'glpiosquery'),
                'sql'   => ['all' => 'SELECT days, hours, minutes FROM uptime;'],
                // Uptime always changes between two captures, so reporting that
                // it did carries no information — and split across days, hours
                // and minutes it reads as "+1 hour, -47 minutes", which is
                // accurate and actively confusing. What matters is whether the
                // machine rebooted, which the uptime table itself shows.
                'compare' => false,
            ],
            [
                'key'   => 'disk',
                'label' => __('Disk space', 'glpiosquery'),
                'sql'   => [
                    // blocks_available, not blocks_free: the difference is the
                    // root reserve, and reporting space a user cannot use as
                    // free is how a "disk full" ticket gets closed as working.
                    //
                    // Filtered on the *device*, not the filesystem type. A type
                    // blocklist misses things (efivarfs was showing up as a
                    // 0.0 GB "disk"), while requiring /dev/ and excluding loop
                    // devices leaves exactly the volumes a person thinks of as
                    // disks. Measured on a real desktop the naive version
                    // returned 40 rows, 36 of them snap mounts.
                    'linux'   => "SELECT path, type, "
                               . "round(blocks * blocks_size / 1073741824.0, 1) AS size_gb, "
                               . "round(blocks_available * blocks_size / 1073741824.0, 1) AS free_gb "
                               . "FROM mounts WHERE device LIKE '/dev/%' "
                               . "AND device NOT LIKE '/dev/loop%' AND blocks > 0;",
                    'darwin'  => "SELECT path, type, "
                               . "round(blocks * blocks_size / 1073741824.0, 1) AS size_gb, "
                               . "round(blocks_available * blocks_size / 1073741824.0, 1) AS free_gb "
                               . "FROM mounts WHERE device LIKE '/dev/%' AND blocks > 0;",
                    // free_space of -1 means osquery could not read it; showing
                    // that as 0 would claim a full disk we never measured.
                    'windows' => "SELECT device_id, file_system, "
                               . "round(size / 1073741824.0, 1) AS size_gb, "
                               . "round(free_space / 1073741824.0, 1) AS free_gb "
                               . "FROM logical_drives WHERE free_space >= 0;",
                ],
            ],
            [
                'key'   => 'memory',
                'label' => __('Memory', 'glpiosquery'),
                'sql'   => [
                    'linux' => "SELECT round(memory_total / 1048576.0, 0) AS total_mb, "
                             . "round(memory_available / 1048576.0, 0) AS available_mb, "
                             . "round(swap_total / 1048576.0, 0) AS swap_total_mb, "
                             . "round(swap_free / 1048576.0, 0) AS swap_free_mb FROM memory_info;",
                    // memory_info is Linux-only; elsewhere the installed total
                    // is all osquery offers, and the process list below is what
                    // actually answers "what is eating it".
                    'all'   => "SELECT round(physical_memory / 1048576.0, 0) AS total_mb FROM system_info;",
                ],
            ],
            [
                'key'   => 'top_processes',
                'label' => __('Top processes by memory', 'glpiosquery'),
                'sql'   => [
                    'all' => "SELECT name, pid, round(resident_size / 1048576.0, 1) AS rss_mb "
                           . "FROM processes ORDER BY resident_size DESC LIMIT 8;",
                ],
            ],
            [
                'key'   => 'logged_in',
                'label' => __('Active user', 'glpiosquery'),
                'sql'   => [
                    // Derived from running processes on Linux, not from
                    // logged_in_users. osquery reads utmp there, and a modern
                    // systemd desktop does not populate it — measured on Ubuntu
                    // 26.04 with a user plainly sitting at the machine,
                    // logged_in_users returned zero rows, unfiltered. Counting
                    // processes owned by real (uid >= 1000) accounts answers
                    // the question the technician is actually asking.
                    'linux' => "SELECT u.username, u.uid, count(p.pid) AS processes "
                             . "FROM users u JOIN processes p ON p.uid = u.uid "
                             . "WHERE u.uid >= 1000 AND u.username NOT LIKE '%nobody%' "
                             . "GROUP BY u.username, u.uid ORDER BY processes DESC;",
                    // Windows and macOS do populate their session tables.
                    'all'   => "SELECT user, type, tty, host FROM logged_in_users "
                             . "WHERE type IN ('user','active');",
                ],
            ],
        ];
    }

    /**
     * The SQL for a probe on a given platform, or null when it has none.
     *
     * @param array<string,string> $sql
     */
    public static function sqlFor(array $sql, string $platform): ?string
    {
        $platform = QueryCatalog::normalisePlatform($platform);

        return $sql[$platform] ?? $sql['all'] ?? null;
    }

    /**
     * Capture evidence for a ticket about an asset.
     *
     * @return int the evidence id, or 0 when nothing was captured
     */
    public static function capture(
        int $tickets_id,
        string $itemtype,
        int $items_id,
        string $trigger = self::LINKED
    ): int {
        /** @var \DBmysql $DB */
        global $DB;

        // A manual capture runs even with the feature switched off: someone
        // pressed a button on this ticket, which is a clearer instruction than
        // a global default, and it is the only way to compare before and after.
        if ($tickets_id <= 0 || (!self::enabled() && $trigger !== self::MANUAL)) {
            return 0;
        }

        // Only computers carry an osquery agent. Printers and phones land here
        // too and there is nothing to ask them.
        if ($itemtype !== 'Computer') {
            return 0;
        }

        // The dedupe window exists to stop a fiddly morning of attaching and
        // detaching assets filling the timeline. A technician pressing "capture
        // now" is doing the opposite — deliberately asking for a second reading
        // to compare against the first — so it does not apply to them.
        if ($trigger !== self::MANUAL && self::capturedRecently($tickets_id, $itemtype, $items_id)) {
            return 0;
        }

        $agent = self::agentFor($itemtype, $items_id);
        if ($agent === null) {
            return 0;
        }

        $DB->insert(self::TABLE, [
            'tickets_id'                   => $tickets_id,
            'itemtype'                     => $itemtype,
            'items_id'                     => $items_id,
            'plugin_glpiosquery_agents_id' => (int) $agent['id'],
            'status'                       => self::PENDING,
            'trigger_type'                 => $trigger,
            'date_creation'                => date('Y-m-d H:i:s'),
        ]);
        $evidences_id = $DB->insertId();

        $platform = (string) ($agent['platform'] ?? '');
        $launched = 0;

        foreach (self::probes() as $probe) {
            $sql = self::sqlFor($probe['sql'], $platform);
            if ($sql === null) {
                continue;
            }

            $campaigns_id = Campaign::launch(
                sprintf('evidence: %s', $probe['label']),
                $sql,
                [(int) $agent['id']],
                0,
                (int) ($agent['entities_id'] ?? 0)
            );

            $DB->update(
                Campaign::TABLE,
                ['plugin_glpiosquery_evidences_id' => $evidences_id],
                ['id' => $campaigns_id]
            );
            $launched++;
        }

        if ($launched === 0) {
            $DB->update(self::TABLE, ['status' => self::SKIPPED], ['id' => $evidences_id]);
            return 0;
        }

        return $evidences_id;
    }

    private static function capturedRecently(int $tickets_id, string $itemtype, int $items_id): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $since = date('Y-m-d H:i:s', time() - self::DEDUPE_SECONDS);

        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::TABLE,
                'WHERE'  => [
                    'tickets_id'    => $tickets_id,
                    'itemtype'      => $itemtype,
                    'items_id'      => $items_id,
                    'date_creation' => ['>', $since],
                ],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return true;
        }

        return false;
    }

    /** The agent for an asset, or null when it is not osquery-managed. */
    private static function agentFor(string $itemtype, int $items_id): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'FROM'  => Node::TABLE,
                'WHERE' => [
                    'itemtype'   => $itemtype,
                    'items_id'   => $items_id,
                    'is_deleted' => 0,
                    'is_active'  => 1,
                ],
                'ORDER' => ['last_seen DESC'],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }

    /**
     * Write up every capture that has finished or run out of time.
     *
     * Driven from the maintenance cron rather than from result ingest: the
     * probes complete one at a time, and a followup per probe would bury the
     * timeline. One capture becomes one followup, whether or not every probe
     * answered.
     *
     * @return int followups written
     */
    public static function renderPending(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $deadline = date('Y-m-d H:i:s', time() - self::COLLECT_SECONDS);
        $written  = 0;

        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => ['status' => self::PENDING],
                'ORDER' => ['id'],
                'LIMIT' => 50,
            ]) as $evidence
        ) {
            $campaigns = self::campaignsFor((int) $evidence['id']);
            if ($campaigns === []) {
                $DB->update(self::TABLE, ['status' => self::SKIPPED], ['id' => $evidence['id']]);
                continue;
            }

            $settled = true;
            foreach ($campaigns as $campaign) {
                if ((string) $campaign['status'] === 'running') {
                    $settled = false;
                    break;
                }
            }

            // Not everything is in, and there is still time on the clock.
            if (!$settled && (string) $evidence['date_creation'] > $deadline) {
                continue;
            }

            if (self::writeFollowup($evidence, $campaigns, self::previousFor($evidence))) {
                $written++;
            }
        }

        return $written;
    }

    /** @return array<int,array<string,mixed>> */
    private static function campaignsFor(int $evidences_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => Campaign::TABLE,
                'WHERE' => ['plugin_glpiosquery_evidences_id' => $evidences_id],
                'ORDER' => ['id'],
            ]) as $row
        ) {
            $out[] = $row;
        }

        return $out;
    }

    /**
     * @param array<string,mixed>            $evidence
     * @param array<int,array<string,mixed>> $campaigns
     */
    /**
     * The most recent already-written capture for the same ticket and asset.
     *
     * @param array<string,mixed> $evidence
     * @return array{when:string,rows:array<string,array>}|array{}
     */
    private static function previousFor(array $evidence): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $earlier = null;
        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => [
                    'tickets_id' => (int) $evidence['tickets_id'],
                    'itemtype'   => (string) $evidence['itemtype'],
                    'items_id'   => (int) $evidence['items_id'],
                    'status'     => self::RENDERED,
                    'id'         => ['<', (int) $evidence['id']],
                ],
                'ORDER' => ['id DESC'],
                'LIMIT' => 1,
            ]) as $row
        ) {
            $earlier = $row;
        }

        if ($earlier === null) {
            return [];
        }

        $rows = [];
        foreach (self::campaignsFor((int) $earlier['id']) as $campaign) {
            $label = preg_replace('/^evidence:\s*/', '', (string) $campaign['name']);
            $rows[$label] = self::rowsFor((int) $campaign['id']);
        }

        return ['when' => (string) $earlier['date_creation'], 'rows' => $rows];
    }

    private static function writeFollowup(array $evidence, array $campaigns, array $previous = []): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $sections = [];
        foreach ($campaigns as $campaign) {
            $label = preg_replace('/^evidence:\s*/', '', (string) $campaign['name']);
            $rows  = self::rowsFor((int) $campaign['id']);

            $sections[] = ['label' => $label, 'rows' => $rows, 'status' => (string) $campaign['status']];
        }

        $body = self::renderHtml($evidence, $sections, $previous);

        $followup = new ITILFollowup();
        $followups_id = $followup->add([
            'itemtype'   => Ticket::class,
            'items_id'   => (int) $evidence['tickets_id'],
            'content'    => $body,
            'is_private' => self::followupIsPrivate() ? 1 : 0,
            // No requester: this is the system reporting, and attributing it to
            // whoever happened to open the ticket would be a lie in the audit
            // trail.
            'users_id'   => 0,
        ]);

        if (!$followups_id) {
            return false;
        }

        $DB->update(self::TABLE, [
            'status'       => self::RENDERED,
            'followups_id' => (int) $followups_id,
            'rendered_at'  => date('Y-m-d H:i:s'),
        ], ['id' => $evidence['id']]);

        return true;
    }

    /** @return array<int,array<string,mixed>> */
    private static function rowsFor(int $campaigns_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => Campaign::ROW_TABLE,
                'WHERE' => ['plugin_glpiosquery_campaigns_id' => $campaigns_id],
                'LIMIT' => 25,
            ]) as $row
        ) {
            $decoded = json_decode((string) $row['row_data'], true);
            if (is_array($decoded)) {
                $out[] = $decoded;
            }
        }

        return $out;
    }

    /**
     * Render the "what changed" block.
     *
     * @param array<int,array{label:string,rows:array,status:string}> $sections
     * @param array<string,array<int,array<string,mixed>>>            $previous
     */
    private static function renderComparison(array $sections, array $previous): string
    {
        $changes = [];
        $when    = '';

        $comparable = [];
        foreach (self::probes() as $probe) {
            if ($probe['compare'] ?? true) {
                $comparable[(string) $probe['label']] = true;
            }
        }

        foreach ($sections as $section) {
            $label = (string) $section['label'];
            if (!isset($comparable[$label])) {
                continue;
            }

            $was = $previous['rows'][$label] ?? null;
            if ($was === null) {
                continue;
            }

            foreach (self::compare($section['rows'], $was) as $change) {
                $change['section'] = $label;
                $changes[] = $change;
            }
        }

        $when = (string) ($previous['when'] ?? '');

        if ($changes === []) {
            return "<p class='text-muted'>"
                 . sprintf(
                     __('Nothing measurable changed since the capture at %s.', 'glpiosquery'),
                     htmlspecialchars($when)
                 )
                 . "</p>";
        }

        $html  = "<p><strong>"
               . sprintf(__('Changes since %s', 'glpiosquery'), htmlspecialchars($when))
               . "</strong></p>";
        $html .= "<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse'>";
        $html .= "<tr><th align='left'>" . __('What', 'glpiosquery') . "</th>"
               . "<th align='left'>" . __('Before', 'glpiosquery') . "</th>"
               . "<th align='left'>" . __('After', 'glpiosquery') . "</th>"
               . "<th align='left'>" . __('Change', 'glpiosquery') . "</th></tr>";

        foreach ($changes as $change) {
            $what = $change['section'] . ' · ' . $change['column'];
            if ($change['label'] !== '') {
                $what = $change['section'] . ' · ' . $change['label'] . ' · ' . $change['column'];
            }

            // Signed, and left uncoloured: more free disk is good, more uptime
            // is usually bad, and a table that guesses which way is which will
            // eventually tell a technician that a full disk is an improvement.
            $delta = sprintf('%+.1f', $change['delta']);

            $html .= "<tr><td>" . htmlspecialchars($what) . "</td>"
                   . "<td>" . htmlspecialchars($change['before']) . "</td>"
                   . "<td>" . htmlspecialchars($change['after']) . "</td>"
                   . "<td>" . htmlspecialchars($delta) . "</td></tr>";
        }

        return $html . "</table>";
    }

    /**
     * Compare a probe's rows against the same probe's previous rows.
     *
     * The point of a second capture is almost always to show that something
     * moved — memory freed, disk reclaimed, a machine actually rebooted. Making
     * the technician scroll up and eyeball two tables to establish that is how
     * "we fixed it" ends up asserted rather than shown.
     *
     * Rows are keyed by their first column when there are several (disk by
     * mount path), and compared column-by-column when a probe returns a single
     * row (memory). Only numeric columns produce a delta; a version string
     * changing is not an improvement that can be expressed as +/-.
     *
     * @param array<int,array<string,mixed>> $now
     * @param array<int,array<string,mixed>> $before
     * @return array<int,array{label:string,column:string,before:string,after:string,delta:float}>
     */
    public static function compare(array $now, array $before): array
    {
        if ($now === [] || $before === []) {
            return [];
        }

        $columns = array_keys($now[0]);
        if ($columns === []) {
            return [];
        }

        $key = $columns[0];

        // Whether the probe has a natural key, decided by the first column
        // being a name rather than a number. Memory returns one row whose
        // leading column is a quantity (total_mb) and has no key; disk returns
        // rows keyed by mount path.
        //
        // Counting rows is not enough to tell them apart: a keyed probe can
        // return a single row too, and treating that as keyless compares
        // whatever happens to be there — a newly-mounted USB stick against the
        // root filesystem, reported as a 831 GB improvement. Nor can the key
        // column simply be matched, because a RAM upgrade changes total_mb,
        // which is precisely the change worth showing.
        $single = count($now) === 1
               && count($before) === 1
               && is_numeric((string) ($now[0][$key] ?? ''));

        $current  = self::foldByKey($now, $key, $columns, $single);
        $previous = self::foldByKey($before, $key, $columns, $single);

        $out = [];
        foreach ($current as $id => $row) {
            $was = $previous[$id] ?? null;
            if ($was === null) {
                continue;
            }

            foreach ($columns as $column) {
                if (!$single && $column === $key) {
                    continue;
                }
                if (in_array($column, self::IDENTIFIER_COLUMNS, true)) {
                    continue;
                }

                if (!isset($row[$column], $was[$column])) {
                    continue;
                }

                $delta = $row[$column] - $was[$column];
                if (abs($delta) < 0.05) {
                    continue; // noise, not news
                }

                $out[] = [
                    'label'  => (string) $id,
                    'column' => $column,
                    'before' => self::trimNumber($was[$column]),
                    'after'  => self::trimNumber($row[$column]),
                    'delta'  => $delta,
                ];
            }
        }

        return $out;
    }

    /**
     * Collapse rows to one numeric total per key.
     *
     * Several rows can legitimately share a key — a browser contributes eight
     * `msedge` processes to the top-eight list — and pairing them off
     * positionally compares unrelated processes to each other. Summing per name
     * is also the figure anyone actually wants: not "did this particular PID
     * shrink" but "is the browser still holding a gigabyte".
     *
     * @param array<int,array<string,mixed>> $rows
     * @param array<int,string>              $columns
     * @return array<string,array<string,float>>
     */
    private static function foldByKey(array $rows, string $key, array $columns, bool $single): array
    {
        $out = [];
        foreach ($rows as $row) {
            $id = $single ? '' : (string) ($row[$key] ?? '');

            foreach ($columns as $column) {
                $value = (string) ($row[$column] ?? '');
                if ($value === '' || !is_numeric($value)) {
                    continue;
                }

                $out[$id][$column] = ($out[$id][$column] ?? 0.0) + (float) $value;
            }
        }

        return $out;
    }

    private static function trimNumber(float $value): string
    {
        return rtrim(rtrim(number_format($value, 1, '.', ''), '0'), '.');
    }

    /**
     * Build the followup body.
     *
     * Kept as its own method with no database access so the output can be
     * tested against known probe results — this is the part a technician
     * actually reads, and a mistake in it is a mistake in every ticket.
     *
     * @param array<string,mixed> $evidence
     * @param array<int,array{label:string,rows:array,status:string}> $sections
     */
    public static function renderHtml(array $evidence, array $sections, array $previous = []): string
    {
        $when   = (string) ($evidence['date_creation'] ?? '');
        $manual = (string) ($evidence['trigger_type'] ?? '') === self::MANUAL;

        $html  = "<p><strong>"
               . ($manual
                    ? __('Machine state, captured on request', 'glpiosquery')
                    : __('Machine state when this ticket was raised', 'glpiosquery'))
               . "</strong>";
        if ($when !== '') {
            $html .= " <span class='text-muted'>(" . htmlspecialchars($when) . ")</span>";
        }
        $html .= "</p>";

        // What changed goes first. On a re-capture that is the entire reason
        // anyone pressed the button, and burying it under six tables of
        // unchanged facts makes them find it themselves.
        if ($previous !== []) {
            $html .= self::renderComparison($sections, $previous);
        }

        // An empty answer and no answer are different facts, and conflating
        // them is how a technician concludes a machine is fine when nobody
        // successfully asked it. "Nothing to report" is a measurement;
        // "did not reply" is a symptom.
        $empty  = [];
        $silent = [];

        foreach ($sections as $section) {
            $label = htmlspecialchars((string) $section['label']);

            if ($section['rows'] === []) {
                if ($section['status'] === 'complete') {
                    $empty[] = $label;
                } else {
                    $silent[] = $label;
                }
                continue;
            }

            $html .= "<p><strong>" . $label . "</strong></p>";
            $html .= "<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse'>";

            $columns = array_keys($section['rows'][0]);
            $html   .= "<tr>";
            foreach ($columns as $column) {
                $html .= "<th align='left'>" . htmlspecialchars((string) $column) . "</th>";
            }
            $html .= "</tr>";

            foreach ($section['rows'] as $row) {
                $html .= "<tr>";
                foreach ($columns as $column) {
                    $html .= "<td>" . htmlspecialchars((string) ($row[$column] ?? '')) . "</td>";
                }
                $html .= "</tr>";
            }
            $html .= "</table>";
        }

        if ($empty !== []) {
            $html .= "<p class='text-muted'>"
                   . sprintf(
                       __('Nothing to report for: %s (the machine answered, with no rows).', 'glpiosquery'),
                       implode(', ', $empty)
                   )
                   . "</p>";
        }

        if ($silent !== []) {
            $html .= "<p class='text-muted'>"
                   . sprintf(
                       __('No answer for: %s. The machine may be offline, asleep or off the network.', 'glpiosquery'),
                       implode(', ', $silent)
                   )
                   . "</p>";
        }

        return $html;
    }
}
