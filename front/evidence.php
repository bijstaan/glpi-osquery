<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * "Capture now" from a ticket's Machine state tab.
 *
 * A plain form POST rather than an AJAX call: the result is not something to
 * show inline — the probes take a round trip to answer and the write-up lands
 * in the timeline a moment later — so the honest interaction is "asked, come
 * back in a moment", which a redirect with a message expresses exactly.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\TicketEvidence;
use GlpiPlugin\Glpiosquery\Url;

Session::checkRight('plugin_glpiosquery_agent', READ);

// No Session::checkCSRF() here on purpose. GLPI 11's CheckCsrfListener already
// validates the token for every non-XHR POST to a legacy script, and does so
// with preserve_token = false — which consumes it. Checking again always fails.

$tickets_id = (int) ($_POST['tickets_id'] ?? 0);
$itemtype   = (string) ($_POST['itemtype'] ?? '');
$items_id   = (int) ($_POST['items_id'] ?? 0);

if (empty($_POST['capture_now']) || $tickets_id <= 0) {
    Html::back();
}

// The ticket has to be one this user may actually read, or the button becomes
// a way to point the fleet at any machine by editing a form field.
$ticket = new Ticket();
if (!$ticket->getFromDB($tickets_id) || !$ticket->canViewItem()) {
    Session::addMessageAfterRedirect(
        __('You are not allowed to see that ticket.', 'glpiosquery'),
        false,
        ERROR
    );
    Html::redirect(Url::to('front/ticket.php'));
}

$evidences_id = TicketEvidence::capture($tickets_id, $itemtype, $items_id, TicketEvidence::MANUAL);

if ($evidences_id > 0) {
    Session::addMessageAfterRedirect(
        __('Asking the machine now. The reading appears in the timeline within a minute or two.', 'glpiosquery')
    );
} else {
    Session::addMessageAfterRedirect(
        __('Nothing to ask: that asset has no active osquery agent.', 'glpiosquery'),
        false,
        WARNING
    );
}

Html::redirect(Ticket::getFormURLWithID($tickets_id));
