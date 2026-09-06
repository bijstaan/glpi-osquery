<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Create or edit a saved query.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\ConsoleMenu;
use GlpiPlugin\Glpiosquery\SavedQuery;

$query = new SavedQuery();

if (isset($_POST['add'])) {
    $query->check(-1, CREATE, $_POST);
    if ($newID = $query->add($_POST)) {
        Html::redirect($query->getFormURLWithID($newID));
    }
    Html::back();
} elseif (isset($_POST['update'])) {
    $query->check((int) $_POST['id'], UPDATE);
    $query->update($_POST);
    Html::back();
} elseif (isset($_POST['purge'])) {
    $query->check((int) $_POST['id'], PURGE);
    $query->delete($_POST, true);
    $query->redirectToList();
}

Session::checkRight(SavedQuery::$rightname, READ);

Html::header(
    SavedQuery::getTypeName(1),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector(ConsoleMenu::class, 'tools')
        : 'tools',
    SavedQuery::class
);

$id = (int) ($_GET['id'] ?? -1);
// Scope wrapper: this page is otherwise entirely core-rendered markup,
// which the plugin's dark-theme CSS (public/css/osquery.css) could
// structurally never reach.
echo "<div class='glpiosquery-surface'>";
$query->display(['id' => $id]);
echo "</div>";

Html::footer();
