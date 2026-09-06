<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonDBTM;
use Html;
use Session;

/**
 * A named, shared live query.
 *
 * This is what makes the split between the two live-query rights mean
 * something. `plugin_glpiosquery_livequery` is meant to be the safe grant —
 * run the questions someone has already vetted — while
 * `plugin_glpiosquery_rawsql` is the open window onto every endpoint. Without a
 * library the safe grant permits nothing at all, so in practice everybody ends
 * up with raw SQL, which is the opposite of the intent.
 */
class SavedQuery extends CommonDBTM
{
    public static $rightname = 'plugin_glpiosquery_pack';

    public $dohistory = true;

    public static function getTypeName($nb = 0)
    {
        return _n('Saved query', 'Saved queries', $nb, 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-bookmark';
    }

    public function isEntityAssign()
    {
        return true;
    }

    /**
     * Queries this user may run, narrowed to their entity scope.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function selectable(?string $platform = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $where = [
            'is_active'   => 1,
            'entities_id' => Targeting::entityScope([]),
        ];

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => $where,
                'ORDER' => ['name'],
            ]) as $row
        ) {
            // A query written for one platform is offered everywhere in the
            // fleet console, but hidden on a device that cannot answer it.
            $target = (string) ($row['platform'] ?? 'all');
            if (
                $platform !== null && $platform !== '' && $target !== '' && $target !== 'all'
                && !Node::platformMatches($target, $platform)
            ) {
                continue;
            }
            $out[] = $row;
        }

        return $out;
    }

    /** The stored SQL for an id, or null. Never trust a client-supplied query. */
    public static function sqlFor(int $id): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => [
                    'id'          => $id,
                    'is_active'   => 1,
                    'entities_id' => Targeting::entityScope([]),
                ],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }

    public function rawSearchOptions()
    {
        $options = [];

        $options[] = ['id' => 'common', 'name' => self::getTypeName(2)];

        $options[] = [
            'id'            => '1',
            'table'         => self::getTable(),
            'field'         => 'name',
            'name'          => __('Name'),
            'datatype'      => 'itemlink',
            'massiveaction' => false,
        ];
        $options[] = [
            'id'       => '2',
            'table'    => self::getTable(),
            'field'    => 'description',
            'name'     => __('Description'),
            'datatype' => 'text',
        ];
        $options[] = [
            'id'       => '3',
            'table'    => self::getTable(),
            'field'    => 'sql_query',
            'name'     => __('Query', 'glpiosquery'),
            'datatype' => 'text',
        ];
        $options[] = [
            'id'       => '4',
            'table'    => self::getTable(),
            'field'    => 'platform',
            'name'     => __('Platform', 'glpiosquery'),
            'datatype' => 'string',
        ];
        $options[] = [
            'id'       => '5',
            'table'    => self::getTable(),
            'field'    => 'is_active',
            'name'     => __('Active'),
            'datatype' => 'bool',
        ];
        $options[] = [
            'id'       => '6',
            'table'    => self::getTable(),
            'field'    => 'date_mod',
            'name'     => __('Last update'),
            'datatype' => 'datetime',
            'massiveaction' => false,
        ];
        $options[] = [
            'id'            => '80',
            'table'         => 'glpi_entities',
            'field'         => 'completename',
            'name'          => __('Entity'),
            'datatype'      => 'dropdown',
            'massiveaction' => false,
        ];

        return $options;
    }

    /**
     * Reject anything that is not a single read-only SELECT before it is saved.
     *
     * Checking at save time as well as at launch time matters: a saved query is
     * run by people who were trusted with the *safe* right precisely because
     * they are not expected to audit the SQL themselves.
     */
    public function prepareInputForAdd($input)
    {
        return $this->validate($input);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->validate($input);
    }

    private function validate($input)
    {
        if (isset($input['sql_query'])) {
            $reason = QueryCatalog::reject((string) $input['sql_query']);
            if ($reason !== null) {
                Session::addMessageAfterRedirect($reason, false, ERROR);
                return false;
            }
        }

        if (isset($input['name']) && trim((string) $input['name']) === '') {
            Session::addMessageAfterRedirect(__('A saved query needs a name.', 'glpiosquery'), false, ERROR);
            return false;
        }

        return $input;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Name') . "</td><td>";
        echo Html::input('name', ['value' => $this->fields['name'] ?? '', 'size' => 40]);
        echo "</td>";
        echo "<td>" . __('Active') . "</td><td>";
        \Dropdown::showYesNo('is_active', $this->fields['is_active'] ?? 1);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Platform', 'glpiosquery') . "</td><td>";
        \Dropdown::showFromArray('platform', [
            'all'     => __('Any', 'glpiosquery'),
            'linux'   => 'Linux',
            'darwin'  => 'macOS',
            'windows' => 'Windows',
        ], ['value' => $this->fields['platform'] ?? 'all']);
        echo "</td>";
        echo "<td>" . __('Description') . "</td><td>";
        echo Html::input('description', ['value' => $this->fields['description'] ?? '', 'size' => 50]);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Query', 'glpiosquery') . "</td>";
        echo "<td colspan='3'>";
        echo "<textarea name='sql_query' rows='6' class='form-control' style='font-family:monospace'>"
           . htmlspecialchars((string) ($this->fields['sql_query'] ?? '')) . "</textarea>";
        echo "<div class='form-text'>"
           . __('A single read-only SELECT. It is validated here as well as when it runs, because the '
              . 'people allowed to run saved queries are exactly the people not expected to audit the SQL.', 'glpiosquery')
           . "</div>";
        echo "</td></tr>";

        $this->showFormButtons($options);

        return true;
    }

    public static function getMenuContent()
    {
        if (!Session::haveRight(self::$rightname, READ)) {
            return false;
        }

        return [
            'title' => self::getTypeName(2),
            'page'  => '/plugins/glpiosquery/front/savedquery.php',
            'icon'  => self::getIcon(),
            'links' => [
                'search' => '/plugins/glpiosquery/front/savedquery.php',
                'add'    => '/plugins/glpiosquery/front/savedquery.form.php',
            ],
        ];
    }

    /**
     * Seed a starting library.
     *
     * Deliberately practical rather than exhaustive: these are the questions
     * support actually asks, and they double as worked examples of the query
     * style for whoever writes the next one.
     */
    public static function seedDefaults(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $defaults = [
            [
                'name'        => 'Who is logged in',
                'description' => 'Interactive sessions on the machine right now.',
                'platform'    => 'all',
                'sql_query'   => "SELECT user, tty, host, datetime(time, 'unixepoch') AS since FROM logged_in_users WHERE type = 'user';",
            ],
            [
                'name'        => 'Disk space',
                'description' => 'Mounted filesystems with free space, largest first.',
                'platform'    => 'linux,darwin',
                'sql_query'   => "SELECT path, type, round((blocks * blocks_size) / 1073741824.0, 1) AS total_gb, "
                               . "round((blocks_available * blocks_size) / 1073741824.0, 1) AS free_gb "
                               . "FROM mounts WHERE device LIKE '/dev/%' ORDER BY total_gb DESC;",
            ],
            [
                'name'        => 'Top memory consumers',
                'description' => 'The ten processes using the most resident memory.',
                'platform'    => 'all',
                'sql_query'   => 'SELECT name, pid, uid, round(resident_size / 1048576.0, 1) AS rss_mb '
                               . 'FROM processes ORDER BY resident_size DESC LIMIT 10;',
            ],
            [
                'name'        => 'Listening network ports',
                'description' => 'What is accepting connections, and which process owns it.',
                'platform'    => 'all',
                'sql_query'   => 'SELECT DISTINCT p.name, p.path, l.port, l.protocol, l.address '
                               . 'FROM listening_ports l LEFT JOIN processes p ON p.pid = l.pid '
                               . 'WHERE l.port != 0 ORDER BY l.port;',
            ],
            [
                'name'        => 'Uptime',
                'description' => 'How long since the machine last booted.',
                'platform'    => 'all',
                'sql_query'   => 'SELECT days, hours, minutes, total_seconds FROM uptime;',
            ],
            [
                'name'        => 'Recently installed packages',
                'description' => 'Debian/Ubuntu packages, newest first — useful after an unexpected change.',
                'platform'    => 'linux',
                'sql_query'   => 'SELECT name, version, arch, size FROM deb_packages ORDER BY name;',
            ],
            [
                'name'        => 'Disk encryption status',
                'description' => 'Whether each volume is encrypted.',
                'platform'    => 'linux,darwin',
                'sql_query'   => 'SELECT name, encrypted, type, encryption_status FROM disk_encryption;',
            ],
            [
                'name'        => 'Connected monitors',
                'description' => 'Displays attached to the machine. Needs the glpi-edid extension shipped with the agent.',
                'platform'    => 'linux',
                'sql_query'   => 'SELECT connector, preferred_mode, status, bytes FROM glpi_edid;',
            ],
        ];

        foreach ($defaults as $query) {
            $exists = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::getTable(),
                'WHERE'  => ['name' => $query['name']],
            ]);
            if (count($exists)) {
                continue;
            }

            $DB->insert(self::getTable(), $query + [
                'entities_id'   => 0,
                'is_recursive'  => 1,
                'is_active'     => 1,
                'users_id'      => 0,
                'date_creation' => date('Y-m-d H:i:s'),
                'date_mod'      => date('Y-m-d H:i:s'),
            ]);
        }
    }
}
