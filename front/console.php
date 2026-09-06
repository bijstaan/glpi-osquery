<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The fleet-wide live query console.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\ConsoleView;
use GlpiPlugin\Glpiosquery\ConsoleMenu;

Session::checkRight('plugin_glpiosquery_livequery', READ);

Html::header(
    __('Live query', 'glpiosquery'),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector(ConsoleMenu::class, 'tools')
        : 'tools',
    ConsoleMenu::class
);

echo "<div class='container-fluid glpiosquery-surface mt-3'>";
ConsoleView::render(['mode' => 'global']);
echo "</div>";

Html::footer();
