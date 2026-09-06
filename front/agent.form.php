<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * A single agent: details, actions, collected data and its log.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Agent;
use GlpiPlugin\Glpiosquery\Node;

Session::checkRight(Agent::$rightname, READ);

$agent = new Agent();
$id    = (int) ($_REQUEST['id'] ?? 0);

// --- actions -----------------------------------------------------------
// Each is a deliberate operator decision, so each needs UPDATE and a token.
$actions = ['quarantine', 'reinstate', 'reenroll', 'reinventory'];
foreach ($actions as $action) {
    if (empty($_POST[$action])) {
        continue;
    }

    Session::checkRight(Agent::$rightname, UPDATE);
    // No Session::checkCSRF() here on purpose. GLPI 11's CheckCsrfListener
    // already validates the token for every non-XHR POST to a legacy script,
    // and it does so with preserve_token = false — which *consumes* the token.
    // Checking it a second time therefore always fails with a 403 on a request
    // that was perfectly valid.

    if (!$agent->getFromDB((int) $_POST['id'])) {
        Html::displayNotFoundError();
    }

    switch ($action) {
        case 'quarantine':
            $agent->quarantine();
            Session::addMessageAfterRedirect(
                __('Agent quarantined. Its credentials are no longer accepted; nothing it reported has been deleted.', 'glpiosquery')
            );
            break;

        case 'reinstate':
            $agent->reinstate();
            Session::addMessageAfterRedirect(__('Agent reinstated.', 'glpiosquery'));
            break;

        case 'reenroll':
            $agent->forceReenroll();
            Session::addMessageAfterRedirect(
                __('Credentials cleared. The endpoint will enrol again on its next request.', 'glpiosquery')
            );
            break;

        case 'reinventory':
            Node::touch((int) $agent->getID(), [
                'inventory_dirty'   => 1,
                'last_inventory_at' => null,
            ]);
            Session::addMessageAfterRedirect(
                __('The asset will be rebuilt from the latest collected results on the next assembly cycle.', 'glpiosquery')
            );
            break;
    }

    // The itemtype's own form URL, not `$_SERVER['PHP_SELF']`: under GLPI 11
    // that is `/index.php`, so redirecting to it after an action lands the
    // technician on the dashboard with their agent nowhere in sight — and the
    // action itself worked, which makes it read as a page that lost the record.
    Html::redirect(Agent::getFormURLWithID((int) $_POST['id']));
}

Html::header(
    Agent::getTypeName(1),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector(Agent::class, 'admin')
        : 'admin',
    Agent::class
);

if ($id > 0 && $agent->getFromDB($id)) {
    // display() rather than showForm(): it is what renders the tab bar around
    // the form, so "Collected data", "Agent log" and History appear. Calling
    // showForm() directly draws the form and silently no tabs.
    $agent->check($id, READ);
    // Scope wrapper: this page is otherwise entirely core-rendered markup,
    // which the plugin's dark-theme CSS (public/css/osquery.css) could
    // structurally never reach.
    echo "<div class='glpiosquery-surface'>";
    $agent->display(['id' => $id]);
    echo "</div>";
} else {
    Html::displayNotFoundError();
}

Html::footer();
