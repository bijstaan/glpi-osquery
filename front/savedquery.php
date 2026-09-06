<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The saved query library.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\ConsoleMenu;
use GlpiPlugin\Glpiosquery\SavedQuery;

Session::checkRight(SavedQuery::$rightname, READ);

// The sector, the menu *entry*, and the option within it — all three, because
// GLPI looks the page's action links up at
// `menu[sector]['content'][item]['options'][option]['links']`. The saved query
// library is registered as an option under the console entry rather than as a
// menu entry of its own, so naming SavedQuery as the item found nothing and the
// page rendered with no Add button. Nothing about that failure is visible: the
// list is correct, it just cannot be added to.
Html::header(
    SavedQuery::getTypeName(2),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector(ConsoleMenu::class, 'tools')
        : 'tools',
    ConsoleMenu::class,
    'savedquery'
);

Search::show(SavedQuery::class);

Html::footer();
