<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * GLPI osquery Inventory.
 *
 * Replaces GLPI's native inventory + GLPI Agent with osquery. The plugin speaks
 * osquery's own TLS remote API (enroll / config / log / distributed), so the
 * thing running on the endpoint is a stock osqueryd rather than bespoke agent
 * code, and it can therefore also do live queries across the fleet.
 *
 * Inventory is not stored privately: snapshot results are assembled into a
 * GLPI-native inventory document and handed to Glpi\Inventory\Inventory, so
 * assets land as ordinary Computers with the import rules engine applied.
 *
 * The wire format was verified against osquery 5.19.0, not taken from
 * documentation.
 */

use Glpi\Http\Firewall;
use Glpi\Http\SessionManager;
use GlpiPlugin\Glpiosquery\Agent;
use GlpiPlugin\Glpiosquery\ComplianceMenu;
use GlpiPlugin\Glpiosquery\ConsoleMenu;
use GlpiPlugin\Glpiosquery\LiveQueryTab;
use GlpiPlugin\Glpiosquery\MonitorTab;
use GlpiPlugin\Glpiosquery\SavedQuery;
use GlpiPlugin\Glpiosquery\TicketEvidence;
use GlpiPlugin\Glpiosquery\TicketEvidenceTab;

define('PLUGIN_GLPIOSQUERY_VERSION', '0.2.1');
define('PLUGIN_GLPIOSQUERY_MIN_GLPI', '11.0');

// Config context for plugin settings (Config::setConfigurationValues).
define('PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT', 'plugin:glpiosquery');

// The osquery version the installers pin and the config page reports.
define('PLUGIN_GLPIOSQUERY_OSQUERY_VERSION', '5.19.0');

function plugin_init_glpiosquery()
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['glpiosquery'] = true;

    // The osquery endpoints are machine-to-machine: authenticated by enrollment
    // secret or node key, never by a GLPI session.
    //
    // Two registrations are needed and they do different jobs. The firewall
    // strategy stops GLPI demanding a logged-in user (without it every request
    // gets the "Access denied" page). Registering the same paths as *stateless*
    // additionally exempts them from the CSRF listener — a machine has no token
    // to present — and, just as importantly, stops GLPI opening a session at
    // all. That last part is not a detail: every agent hits read.php on a timer
    // forever, and a session per heartbeat would mean the fleet generating
    // session writes as its dominant load.
    $endpoints = '#^/front/(enroll|agent-enroll|config|log|read|write|update|refresh)\.php#';
    Firewall::addPluginStrategyForLegacyScripts('glpiosquery', $endpoints, Firewall::STRATEGY_NO_CHECK);
    SessionManager::registerPluginStatelessPath('glpiosquery', $endpoints);

    // Setup-menu entry + the plugin-list gear both reach the config page; the
    // console lives under Tools, where an operator actually looks for it.
    // A section accepts an array of classes, which is how compliance sits
    // alongside the agent list rather than needing a menu of its own.
    $PLUGIN_HOOKS['menu_toadd']['glpiosquery'] = [
        // No 'config' entry: Setup > Plugins already links the settings page,
        // and a Setup-menu row pointing at the same page is a duplicate. The
        // two entries below are not — they are operational pages the Plugins
        // list does not reach.
        'tools'          => ConsoleMenu::class,
        'admin'          => [Agent::class, ComplianceMenu::class],
    ];

    // Registering the class is what puts the agent into GLPI's search engine,
    // giving filtering, saved searches and CSV/PDF export for free.
    Plugin::registerClass(Agent::class, [
        'addtabon' => [Agent::class],
    ]);
    Plugin::registerClass(SavedQuery::class);
    $PLUGIN_HOOKS['config_page']['glpiosquery'] = 'front/settings.php';

    // Theme conformance for every surface the plugin ships (dark-palette
    // muted-text/badge/button rules, scoped to the plugin's own containers
    // — see public/css/osquery.css). Global on purpose: the plugin's
    // surfaces include tabs on core itemtypes (Ticket, Monitor, Computer)
    // and core-rendered form pages, which a per-page <style> cannot cover.
    $PLUGIN_HOOKS['add_css']['glpiosquery'] = 'css/osquery.css';

    /**
     * osquery, offered to glpi-ai's assistant as tools.
     *
     * Registered unconditionally: the hook is only ever read by glpi-ai, so an
     * instance without it pays nothing and the class is never loaded. Guarding
     * on Plugin::isPluginActive('glpiai') here would run a database lookup on
     * every request to avoid assigning an array element.
     *
     * The rights are the console's own, including the free-form SQL right this
     * plugin grants to nobody by default — so nothing here can be done that the
     * technician could not already do by typing it.
     */
    $PLUGIN_HOOKS['glpiai_tools']['glpiosquery'] = [
        GlpiPlugin\Glpiosquery\AiTools::class,
        'all',
    ];

    // "Live query" tab on inventoried assets, shown only where an agent exists.
    Plugin::registerClass(LiveQueryTab::class, ['addtabon' => ['Computer']]);

    // "Display details" on a Monitor: everything decoded from the EDID that
    // GLPI's own monitor model has nowhere to store.
    Plugin::registerClass(MonitorTab::class, ['addtabon' => ['Monitor']]);

    // "Machine state" tab on a ticket: where a technician takes a second
    // reading to show that whatever they did actually moved something.
    Plugin::registerClass(TicketEvidenceTab::class, ['addtabon' => ['Ticket']]);

    // Capture triage evidence when an asset is attached to a ticket.
    //
    // Hooked on the *link* rather than on Ticket creation: at the moment a
    // ticket is inserted its assets are not attached yet, so a Ticket hook sees
    // no machine to ask. Hooking the link also picks up an asset associated
    // later, which is how a ticket that arrives by email gets its evidence.
    $PLUGIN_HOOKS['item_add']['glpiosquery'] = [
        'Item_Ticket' => 'plugin_glpiosquery_item_linked_to_ticket',
    ];
}

function plugin_version_glpiosquery()
{
    return [
        'name'         => 'osquery Inventory',
        'version'      => PLUGIN_GLPIOSQUERY_VERSION,
        'author'       => 'Bijstaan',
        'license'      => 'GPL-3.0-or-later',
        'homepage'     => 'https://github.com/bijstaan/glpi-osquery',
        'requirements' => ['glpi' => ['min' => PLUGIN_GLPIOSQUERY_MIN_GLPI]],
    ];
}

function plugin_glpiosquery_check_prerequisites()
{
    return true;
}

function plugin_glpiosquery_check_config($verbose = false)
{
    return true;
}
