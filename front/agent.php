<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The fleet: a summary, then GLPI's own search engine over the agents.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Agent;
use GlpiPlugin\Glpiosquery\AgentView;

Session::checkRight(Agent::$rightname, READ);

Html::header(
    Agent::getTypeName(2),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector(Agent::class, 'admin')
        : 'admin',
    Agent::class
);

echo "<div class='container-fluid glpiosquery-surface mt-3'>";
AgentView::showFleetSummary();
echo "</div>";

// Search::show gives filtering, sorting, saved searches and export without any
// of it being reimplemented here.
Search::show(Agent::class);

Html::footer();
