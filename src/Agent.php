<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonDBTM;
use CommonGLPI;
use Computer;
use Html;
use Session;

/**
 * An enrolled agent, as a first-class GLPI object.
 *
 * This is deliberately a CommonDBTM over the same table the hot path uses
 * (see Node, which stays a plain static class because the whole fleet hits it
 * on a timer and it must not pay for object hydration). Modelling it properly
 * here buys the GLPI search engine — filtering, sorting, saved searches, CSV
 * and PDF export, entity scoping — none of which is worth hand-rolling.
 *
 * The class name matters: GLPI derives `glpi_plugin_glpiosquery_agents` from
 * it, which is exactly the table Node already writes.
 */
class Agent extends CommonDBTM
{
    public static string $rightname = 'plugin_glpiosquery_agent';

    public bool $dohistory = true;

    /** last_seen changes on every check-in; logging it would drown the history. */
    public array $history_blacklist = ['last_seen', 'has_pending', 'accelerate_until', 'inventory_dirty'];

    public static function getTypeName($nb = 0)
    {
        return _n('osquery agent', 'osquery agents', $nb, 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-radar';
    }

    public function isEntityAssign()
    {
        return true;
    }

    /**
     * Is this agent in contact?
     *
     * "Online" means it has checked in within the configured window — which is
     * a fact about the last few seconds, not about when it last inventoried.
     * Those two are routinely hours apart and conflating them is how a healthy
     * machine gets mistaken for a dead one.
     */
    public function isOnline(): bool
    {
        $settings = \Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $window   = max(60, (int) ($settings['offline_after'] ?? 900));

        $seen = $this->fields['last_seen'] ?? null;

        return $seen !== null && strtotime((string) $seen) > time() - $window;
    }

    public static function statusBadge(?string $last_seen, int $window, bool $active = true, bool $deleted = false): string
    {
        if ($deleted) {
            return "<span class='badge bg-secondary'>" . __('Deleted') . "</span>";
        }
        if (!$active) {
            return "<span class='badge bg-red'>" . __('Quarantined', 'glpiosquery') . "</span>";
        }

        $seen = $last_seen !== null ? strtotime($last_seen) : 0;
        if ($seen > time() - $window) {
            return "<span class='badge bg-green'>" . __('Online', 'glpiosquery') . "</span>";
        }

        if ($seen === 0) {
            return "<span class='badge bg-secondary'>" . __('Never seen', 'glpiosquery') . "</span>";
        }

        return "<span class='badge bg-orange'>" . __('Offline', 'glpiosquery') . "</span>";
    }

    /**
     * Search options.
     *
     * Deliberately generous: the point of a fleet view is answering questions
     * like "which machines are on an old agent", "what has not inventoried this
     * week", "show me every Windows box in this entity" — all of which are
     * filters, not screens someone should have to write SQL for.
     */
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
            'field'    => 'id',
            'name'     => __('ID'),
            'datatype' => 'number',
            'massiveaction' => false,
        ];

        $options[] = [
            'id'       => '3',
            'table'    => self::getTable(),
            'field'    => 'platform',
            'name'     => __('Platform', 'glpiosquery'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '4',
            'table'    => self::getTable(),
            'field'    => 'os_name',
            'name'     => __('Operating system'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '5',
            'table'    => self::getTable(),
            'field'    => 'os_version',
            'name'     => __('Operating system version'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '6',
            'table'    => self::getTable(),
            'field'    => 'agent_version',
            'name'     => __('Agent version', 'glpiosquery'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '7',
            'table'    => self::getTable(),
            'field'    => 'osquery_version',
            'name'     => __('osquery version', 'glpiosquery'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '8',
            'table'    => self::getTable(),
            'field'    => 'last_seen',
            'name'     => __('Last check-in', 'glpiosquery'),
            'datatype' => 'datetime',
        ];

        $options[] = [
            'id'       => '9',
            'table'    => self::getTable(),
            'field'    => 'last_inventory_at',
            'name'     => __('Last inventory', 'glpiosquery'),
            'datatype' => 'datetime',
        ];

        $options[] = [
            'id'       => '10',
            'table'    => self::getTable(),
            'field'    => 'arch',
            'name'     => __('Architecture', 'glpiosquery'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '11',
            'table'    => self::getTable(),
            'field'    => 'remote_addr',
            'name'     => __('Address', 'glpiosquery'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '12',
            'table'    => self::getTable(),
            'field'    => 'deviceid',
            'name'     => __('Device id', 'glpiosquery'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '13',
            'table'    => self::getTable(),
            'field'    => 'is_active',
            'name'     => __('Active'),
            'datatype' => 'bool',
        ];

        $options[] = [
            'id'       => '14',
            'table'    => self::getTable(),
            'field'    => 'hardware_serial',
            'name'     => __('Serial number'),
            'datatype' => 'string',
        ];

        $options[] = [
            'id'       => '15',
            'table'    => self::getTable(),
            'field'    => 'enrolled_at',
            'name'     => __('Enrolled', 'glpiosquery'),
            'datatype' => 'datetime',
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

    public function defineTabs($options = [])
    {
        $tabs = [];
        $this->addDefaultFormTab($tabs);
        $this->addStandardTab(self::class, $tabs, $options);
        $this->addStandardTab('Log', $tabs, $options);

        return $tabs;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof self) {
            return [
                1 => __('Collected data', 'glpiosquery'),
                2 => __('Agent log', 'glpiosquery'),
            ];
        }

        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!$item instanceof self) {
            return false;
        }

        if ($tabnum == 1) {
            AgentView::showSnapshots($item);
        } else {
            AgentView::showStatusLog($item);
        }

        return true;
    }

    /** The form shown for a single agent. */
    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        AgentView::showForm($this);

        return true;
    }

    /**
     * Quarantine an agent.
     *
     * Deactivating is not the same as deleting: the record and everything it
     * has reported are kept, but the node key stops being accepted, so the
     * endpoint is cut off and must re-enrol to come back. That is the action an
     * operator wants for a machine they no longer trust.
     */
    public function quarantine(): bool
    {
        return (bool) $this->update([
            'id'          => $this->getID(),
            'is_active'   => 0,
            'has_pending' => 0,
        ]);
    }

    public function reinstate(): bool
    {
        return (bool) $this->update(['id' => $this->getID(), 'is_active' => 1]);
    }

    /**
     * Force the agent to enrol again.
     *
     * Clearing the node key makes the next request fail authentication, which
     * osquery answers by re-enrolling with its secret. Nothing else is touched,
     * so the agent keeps its identity and history.
     */
    public function forceReenroll(): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        return (bool) $DB->update(
            self::getTable(),
            ['node_key_hash' => '', 'agent_token_hash' => null],
            ['id' => $this->getID()]
        );
    }

    /** The inventoried asset this agent produced, if any. */
    public function getLinkedItem(): ?CommonDBTM
    {
        $itemtype = (string) ($this->fields['itemtype'] ?? '');
        $items_id = (int) ($this->fields['items_id'] ?? 0);

        if ($itemtype === '' || $items_id === 0 || !class_exists($itemtype)) {
            return null;
        }

        $item = new $itemtype();
        if (!$item instanceof CommonDBTM || !$item->getFromDB($items_id)) {
            return null;
        }

        return $item;
    }

    public static function canView(): bool
    {
        return Session::haveRight(self::$rightname, READ);
    }

    public static function canCreate(): bool
    {
        // Agents create themselves by enrolling; there is no manual add.
        return false;
    }

    public static function getMenuContent()
    {
        if (!self::canView()) {
            return false;
        }

        return [
            'title' => self::getTypeName(2),
            'page'  => '/plugins/glpiosquery/front/agent.php',
            'icon'  => self::getIcon(),
            'links' => [
                'search' => '/plugins/glpiosquery/front/agent.php',
            ],
            // Kept for breadcrumbs and the section's own links. It does NOT
            // put compliance in the navigation — measured: with only this,
            // no compliance entry renders anywhere in the menu. A section
            // does accept an array of classes (Html.php iterates them), which
            // is how setup.php actually surfaces the page.
            'options' => [
                'compliance' => [
                    'title' => ComplianceMenu::getTypeName(),
                    'page'  => '/plugins/glpiosquery/front/compliance.php',
                    'icon'  => ComplianceMenu::getIcon(),
                ],
            ],
        ];
    }
}
