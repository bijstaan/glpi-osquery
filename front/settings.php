<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Setup → osquery Inventory.
 *
 * Tuning knobs, enrollment secrets and the install command.
 *
 * NOTE: the form deliberately has no `action` attribute. Under GLPI 11's front
 * controller `$_SERVER['PHP_SELF']` resolves to /index.php, whose path-info is
 * "/", and any POST to "/" carrying a body is intercepted by
 * CatchInventoryAgentRequestListener and answered with an inventory error. A
 * bare `<form method="post">` posts to the page's own URL and avoids it.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\AgentUpdate;
use GlpiPlugin\Glpiosquery\EnrollSecret;
use GlpiPlugin\Glpiosquery\Menu;
use GlpiPlugin\Glpiosquery\Extension;

Session::checkRight('config', READ);

$context = PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT;

if (!empty($_POST['update_settings'])) {
    Session::checkRight('config', UPDATE);
    // No Session::checkCSRF() here on purpose. GLPI 11's CheckCsrfListener
    // already validates the token for every non-XHR POST to a legacy script,
    // and it does so with preserve_token = false — which *consumes* the token.
    // Checking it a second time therefore always fails with a 403 on a request
    // that was perfectly valid.

    Config::setConfigurationValues($context, [
        'distributed_interval'     => max(1, (int) ($_POST['distributed_interval'] ?? 10)),
        'accelerate_seconds'       => max(10, (int) ($_POST['accelerate_seconds'] ?? 60)),
        'config_refresh'           => max(30, (int) ($_POST['config_refresh'] ?? 300)),
        'logger_tls_period'        => max(1, (int) ($_POST['logger_tls_period'] ?? 10)),
        'campaign_ttl'             => max(60, (int) ($_POST['campaign_ttl'] ?? 900)),
        'offline_after'            => max(60, (int) ($_POST['offline_after'] ?? 900)),
        'statuslog_retention_days' => max(1, (int) ($_POST['statuslog_retention_days'] ?? 7)),
    ]);

    Session::addMessageAfterRedirect(__('Settings saved.', 'glpiosquery'));
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['update_rollout'])) {
    Session::checkRight('config', UPDATE);

    Config::setConfigurationValues($context, [
        'compliance_tickets'    => !empty($_POST['compliance_tickets']) ? 1 : 0,
        'ticket_evidence'         => !empty($_POST['ticket_evidence']) ? 1 : 0,
        'ticket_evidence_private' => !empty($_POST['ticket_evidence_private']) ? 1 : 0,
        'agent_trusted_addresses' => trim((string) ($_POST['agent_trusted_addresses'] ?? '')),
        'update_enabled'        => !empty($_POST['update_enabled']) ? 1 : 0,
        'rollout_percent'       => max(0, min(100, (int) ($_POST['rollout_percent'] ?? 0))),
        'update_check_interval' => max(300, (int) ($_POST['update_check_interval'] ?? 3600)),
    ]);

    Session::addMessageAfterRedirect(__('Update settings saved.', 'glpiosquery'));
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['add_secret'])) {
    Session::checkRight('config', UPDATE);

    $name = trim((string) ($_POST['secret_name'] ?? ''));
    if ($name !== '') {
        EnrollSecret::create($name, (int) ($_POST['secret_entity'] ?? 0));
        Session::addMessageAfterRedirect(__('Enrollment secret created.', 'glpiosquery'));
    }
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['publish_package'])) {
    Session::checkRight('config', UPDATE);

    $error = AgentUpdate::publish([
        'kind'     => (string) ($_POST['pkg_kind'] ?? ''),
        'version'  => (string) ($_POST['pkg_version'] ?? ''),
        'platform' => (string) ($_POST['pkg_platform'] ?? ''),
        'arch'     => (string) ($_POST['pkg_arch'] ?? ''),
        'url'      => (string) ($_POST['pkg_url'] ?? ''),
        'sha256'   => (string) ($_POST['pkg_sha256'] ?? ''),
        'size'     => (int) ($_POST['pkg_size'] ?? 0),
    ]);

    if ($error !== null) {
        Session::addMessageAfterRedirect($error, false, ERROR);
    } else {
        Session::addMessageAfterRedirect(__('Package published.', 'glpiosquery'));
    }
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['retire_package'])) {
    Session::checkRight('config', UPDATE);

    /** @var DBmysql $DB */
    global $DB;
    $DB->delete(AgentUpdate::PACKAGE_TABLE, ['id' => (int) $_POST['retire_package']]);
    Session::addMessageAfterRedirect(
        __('Package withdrawn. Agents already on that version stay on it.', 'glpiosquery')
    );
    Html::redirect($_SERVER['REQUEST_URI']);
}

// Extensions are the one thing on this page that is not governed by the
// `config` right alone. Extension::canManage() also demands a session that can
// see every entity, which is what keeps an entity administrator from pushing a
// root-run binary to their own machines while still allowing an extension to be
// *scoped* to their entity by somebody who can see the whole instance.
if (!empty($_POST['save_extension'])) {
    if (!Extension::canManage()) {
        Session::addMessageAfterRedirect(
            __('Extensions can only be managed by an administrator of the whole instance.', 'glpiosquery'),
            false,
            ERROR
        );
        Html::redirect($_SERVER['REQUEST_URI']);
    }

    $error = Extension::save([
        'name'         => (string) ($_POST['ext_name'] ?? ''),
        'label'        => (string) ($_POST['ext_label'] ?? ''),
        'entities_id'  => (int) ($_POST['ext_entities_id'] ?? 0),
        'is_recursive' => !empty($_POST['ext_is_recursive']),
        'is_active'    => !empty($_POST['ext_is_active']),
        'comment'      => (string) ($_POST['ext_comment'] ?? ''),
    ]);

    if ($error !== null) {
        Session::addMessageAfterRedirect($error, false, ERROR);
    } else {
        Session::addMessageAfterRedirect(__('Extension saved.', 'glpiosquery'));
    }
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['delete_extension'])) {
    if (!Extension::canManage()) {
        Session::addMessageAfterRedirect(
            __('Extensions can only be managed by an administrator of the whole instance.', 'glpiosquery'),
            false,
            ERROR
        );
        Html::redirect($_SERVER['REQUEST_URI']);
    }

    Extension::delete((int) $_POST['delete_extension']);
    Session::addMessageAfterRedirect(
        __('Extension removed. Agents uninstall it on their next check-in.', 'glpiosquery')
    );
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['publish_extension'])) {
    if (!Extension::canManage()) {
        Session::addMessageAfterRedirect(
            __('Extensions can only be managed by an administrator of the whole instance.', 'glpiosquery'),
            false,
            ERROR
        );
        Html::redirect($_SERVER['REQUEST_URI']);
    }

    $error = AgentUpdate::publish([
        'kind'     => AgentUpdate::KIND_EXTENSION,
        'name'     => (string) ($_POST['extpkg_name'] ?? ''),
        'version'  => (string) ($_POST['extpkg_version'] ?? ''),
        'platform' => (string) ($_POST['extpkg_platform'] ?? ''),
        'arch'     => (string) ($_POST['extpkg_arch'] ?? ''),
        'url'      => (string) ($_POST['extpkg_url'] ?? ''),
        'sha256'   => (string) ($_POST['extpkg_sha256'] ?? ''),
        'size'     => (int) ($_POST['extpkg_size'] ?? 0),
    ]);

    if ($error !== null) {
        Session::addMessageAfterRedirect($error, false, ERROR);
    } else {
        Session::addMessageAfterRedirect(__('Extension binary published.', 'glpiosquery'));
    }
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['revoke_secret'])) {
    Session::checkRight('config', UPDATE);

    /** @var DBmysql $DB */
    global $DB;
    $DB->update(EnrollSecret::TABLE, ['is_active' => 0], ['id' => (int) $_POST['revoke_secret']]);

    // A revoked secret can enrol nobody, so the entity rule carrying its tag
    // can only mislead the next person to read the rule collection.
    EnrollSecret::dropEntityRule((int) $_POST['revoke_secret']);

    Session::addMessageAfterRedirect(__('Secret revoked. Enrolled agents are unaffected.', 'glpiosquery'));
    Html::redirect($_SERVER['REQUEST_URI']);
}

Html::header(
    Menu::getTypeName(),
    $_SERVER['PHP_SELF'],
    'config',
    // Breadcrumbed under Plugins: this page is reached from the Plugins list
    // rather than from a Setup-menu entry of its own.
    'plugins'
);

/** @var DBmysql $DB */
global $DB;

$settings = Config::getConfigurationValues($context);
$csrf     = Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);

$base_url = sprintf(
    'https://%s',
    $_SERVER['HTTP_HOST'] ?? 'glpi.example.com'
);

// ---------------------------------------------------------------- fleet state
$counts = ['total' => 0, 'online' => 0];
$offline_after = (int) ($settings['offline_after'] ?? 900);
foreach (
    $DB->request([
        'SELECT' => ['id', 'last_seen'],
        'FROM'   => Node::TABLE,
        'WHERE'  => ['is_deleted' => 0],
    ]) as $row
) {
    $counts['total']++;
    if (!empty($row['last_seen']) && strtotime($row['last_seen']) > time() - $offline_after) {
        $counts['online']++;
    }
}

// Read-only visitors keep the page but lose every control.
//
// READ opens this page and UPDATE changes it, and the two are separately
// grantable — so a profile can legitimately arrive here able to look and not
// touch. Offering the buttons anyway and answering with an access-denied page
// tells them nothing they could have known beforehand.
$can_edit = Session::haveRight('config', UPDATE);

// Dark-palette helper-text rules used to be an inline <style> here, as a
// property override on `.text-muted` — which core's own `!important`
// declaration silently beats, so it never worked. The working fix (redefine
// the --tblr-muted / --tblr-secondary-color VARIABLES inside the plugin
// scope) now ships in public/css/osquery.css, keyed to the
// `glpiosquery-surface` marker this wrapper carries.
echo "<div class='container-fluid glpiosquery-config glpiosquery-surface mt-3' style='max-width:960px'>";

if (!$can_edit) {
    echo "<div class='alert alert-info py-2'>"
       . __('Read only: you can see this configuration but not change it.', 'glpiosquery')
       . '</div>';
}

echo "<div class='row mb-3'><div class='col-12'>";
echo "<div class='alert alert-info'>";
echo "<strong>" . htmlspecialchars((string) $counts['online']) . "</strong> of <strong>"
   . htmlspecialchars((string) $counts['total']) . "</strong> agents online. ";
echo "osquery " . htmlspecialchars(PLUGIN_GLPIOSQUERY_OSQUERY_VERSION) . " is the pinned version.";
echo "</div>";
echo "</div></div>";

// Warranty lookups live on a page of their own: seven vendors with up to eight
// credentials each is more configuration than everything on this page put
// together, and it is a separate decision — nothing leaves the building until
// somebody makes it.
echo "<div class='card mb-3'><div class='card-body d-flex justify-content-between align-items-center'>";
echo "<div>";
echo "<strong>" . __('Warranty lookups', 'glpiosquery') . "</strong><br>";
echo "<span class='text-muted'>"
   . __('Ask Dell, HP, HPE, Lenovo, Apple, Cisco and Fortinet about the serial numbers in this '
      . 'estate, and write what they say onto each asset\'s Financial information tab.', 'glpiosquery')
   . "</span>";
echo "</div>";
echo "<a class='btn btn-outline-primary' href='"
   . GlpiPlugin\Glpiosquery\Url::to('front/warranty.php') . "'>"
   . __('Configure', 'glpiosquery') . "</a>";
echo "</div></div>";

// -------------------------------------------------------------------- settings
echo "<form method='post'>";
echo $csrf;
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
   . __('Fleet tuning', 'glpiosquery') . "</h3></div>";
echo "<div class='card-body'>";

echo "<p class='text-muted'>"
   . __('Check-in interval is the direct trade between live-query responsiveness and server load: '
      . 'it is the worst-case delay before an agent sees a new query, and every agent makes one '
      . 'request per interval whether or not there is work.', 'glpiosquery')
   . "</p>";

$fields = [
    'distributed_interval'     => [__('Check-in interval (s)', 'glpiosquery'), 10],
    'accelerate_seconds'       => [__('Accelerated window after a campaign (s)', 'glpiosquery'), 60],
    'config_refresh'           => [__('Config refresh (s)', 'glpiosquery'), 300],
    'logger_tls_period'        => [__('Log flush period (s)', 'glpiosquery'), 10],
    'campaign_ttl'             => [__('Live query time limit (s)', 'glpiosquery'), 900],
    'offline_after'            => [__('Consider an agent offline after (s)', 'glpiosquery'), 900],
    'statuslog_retention_days' => [__('Keep agent status logs (days)', 'glpiosquery'), 7],
];

echo "<div class='row'>";
foreach ($fields as $key => [$label, $default]) {
    $value = (int) ($settings[$key] ?? $default);
    echo "<div class='col-md-4 mb-3'>";
    echo "<label class='form-label' for='$key'>" . htmlspecialchars($label) . "</label>";
    echo "<input type='number' min='1' class='form-control' id='$key' name='$key' value='"
       . htmlspecialchars((string) $value) . "'>";
    echo "</div>";
}
echo "</div>";

if ($can_edit) {
    echo "<button type='submit' name='update_settings' value='1' class='btn btn-primary'>"
       . __('Save') . "</button>";
}
echo "</div></div>";
echo "</form>";

// ------------------------------------------------------------ enroll secrets
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
   . __('Enrollment secrets', 'glpiosquery') . "</h3></div>";
echo "<div class='card-body'>";

echo "<table class='table table-hover'>";
echo "<thead><tr>"
   . "<th>" . __('Name') . "</th>"
   . "<th>" . __('Entity') . "</th>"
   . "<th>" . __('Enrolments', 'glpiosquery') . "</th>"
   . "<th>" . __('Status') . "</th>"
   . "<th>" . __('Install command', 'glpiosquery') . "</th>"
   . "<th></th>"
   . "</tr></thead><tbody>";

$has_secret = false;
foreach (
    $DB->request([
        'FROM'    => EnrollSecret::TABLE,
        'ORDER'   => ['is_active DESC', 'name'],
    ]) as $row
) {
    $has_secret = true;
    $plain = EnrollSecret::reveal($row);
    $entity = Dropdown::getDropdownName('glpi_entities', (int) $row['entities_id']);

    echo "<tr>";
    echo "<td>" . htmlspecialchars((string) $row['name']) . "</td>";
    echo "<td>" . htmlspecialchars((string) $entity);

    // The entity on the secret is a promise; the rule is what keeps it. Saying
    // so here is what turns "why did this machine import into the root?" into
    // something an administrator can answer without reading the code.
    $tag = EnrollSecret::tagFor((int) $row['id']);
    if ($tag !== null && (int) $row['entities_id'] > 0) {
        $rules_id = EnrollSecret::ruleIdFor((int) $row['id']);
        echo "<div class='text-muted small'>" . htmlspecialchars(sprintf(__('tag %s', 'glpiosquery'), $tag)) . " · ";
        if ($rules_id !== null) {
            echo "<a href='" . htmlspecialchars(RuleImportEntity::getFormURLWithID($rules_id)) . "'>"
               . __('entity rule', 'glpiosquery') . "</a>";
        } else {
            echo "<span class='text-danger'>"
               . __('no entity rule — agents import into the default entity', 'glpiosquery')
               . "</span>";
        }
        echo "</div>";
    }

    echo "</td>";
    echo "<td>" . (int) $row['enroll_count'] . "</td>";
    echo "<td>" . ($row['is_active']
        ? "<span class='badge bg-green'>" . __('Active') . "</span>"
        : "<span class='badge bg-secondary'>" . __('Revoked', 'glpiosquery') . "</span>") . "</td>";
    echo "<td>";
    if ($row['is_active'] && $plain !== null) {
        $cmd = sprintf(
            'glpi-osquery-agent install --server %s --secret %s',
            $base_url,
            $plain
        );
        echo "<code class='user-select-all'>" . htmlspecialchars($cmd) . "</code>";
    } elseif ($row['is_active']) {
        echo "<span class='text-muted'>"
           . __('Unreadable — the GLPI encryption key changed. Issue a new secret.', 'glpiosquery')
           . "</span>";
    } else {
        echo "<span class='text-muted'>&mdash;</span>";
    }
    echo "</td>";
    echo "<td>";
    if ($row['is_active'] && $can_edit) {
        echo "<form method='post' class='d-inline'>" . $csrf
           . "<button type='submit' name='revoke_secret' value='" . (int) $row['id'] . "' "
           . "class='btn btn-sm btn-outline-danger'>" . __('Revoke', 'glpiosquery') . "</button></form>";
    }
    echo "</td>";
    echo "</tr>";
}

if (!$has_secret) {
    echo "<tr><td colspan='6' class='text-muted'>"
       . __('No secrets yet. Create one to enroll your first agent.', 'glpiosquery')
       . "</td></tr>";
}

echo "</tbody></table>";

echo "<form method='post' class='row g-2 align-items-end'>";
echo $csrf;
echo "<div class='col-md-4'>";
echo "<label class='form-label' for='secret_name'>" . __('New secret name', 'glpiosquery') . "</label>";
echo "<input type='text' class='form-control' id='secret_name' name='secret_name' placeholder='"
   . __('e.g. Head office laptops', 'glpiosquery') . "'>";
echo "</div>";
echo "<div class='col-md-4'>";
echo "<label class='form-label'>" . __('Entity') . "</label>";
Entity::dropdown(['name' => 'secret_entity', 'value' => $_SESSION['glpiactive_entity'] ?? 0]);
echo "</div>";
echo "<div class='col-md-4'>";
echo "<button type='submit' name='add_secret' value='1' class='btn btn-success'>"
   . __('Create secret', 'glpiosquery') . "</button>";
echo "</div>";
echo "</form>";

echo "</div></div>";

// ---------------------------------------------------------------- self-update
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
   . __('Agent updates', 'glpiosquery') . "</h3></div>";
echo "<div class='card-body'>";

echo "<p class='text-muted'>"
   . __('Agents ask the server what version they should run. Rollout percentage decides how '
      . 'much of the fleet is told to update: each agent sits in a fixed ring derived from its '
      . 'own device id, so raising the percentage always reaches the same machines first and a '
      . 'bad build is found on a slice of the estate rather than all of it.', 'glpiosquery')
   . "</p>";

echo "<form method='post' class='row g-2 align-items-end mb-3'>";
echo $csrf;
echo "<div class='col-md-3'>";
echo "<label class='form-check form-switch'>";
echo "<input class='form-check-input' type='checkbox' name='update_enabled' value='1'"
   . (!empty($settings['update_enabled']) ? " checked" : "") . ">";
echo "<span class='form-check-label'>" . __('Allow agents to self-update', 'glpiosquery') . "</span>";
echo "</label></div>";

echo "<div class='col-md-3'>";
echo "<label class='form-label' for='rollout_percent'>" . __('Rollout percentage', 'glpiosquery') . "</label>";
echo "<input type='number' min='0' max='100' class='form-control' id='rollout_percent' name='rollout_percent' value='"
   . (int) ($settings['rollout_percent'] ?? 0) . "'>";
echo "</div>";

echo "<div class='col-md-3'>";
echo "<label class='form-label' for='update_check_interval'>" . __('Update check interval (s)', 'glpiosquery') . "</label>";
echo "<input type='number' min='300' class='form-control' id='update_check_interval' name='update_check_interval' value='"
   . (int) ($settings['update_check_interval'] ?? 3600) . "'>";
echo "</div>";

echo "<div class='col-md-3'>";
if ($can_edit) {
    echo "<button type='submit' name='update_rollout' value='1' class='btn btn-primary'>" . __('Save') . "</button>";
}
echo "</div>";

echo "<div class='col-md-6 mt-2'>";
echo "<label class='form-label' for='agent_trusted_addresses'>"
   . __('Addresses allowed to query an agent', 'glpiosquery') . "</label>";
echo "<input type='text' class='form-control' id='agent_trusted_addresses' name='agent_trusted_addresses' value='"
   . htmlspecialchars((string) ($settings['agent_trusted_addresses'] ?? '')) . "'>";
echo "<div class='form-text'>"
   . __('Comma separated hosts, IPs or CIDRs GLPI contacts agents from, for the device page\'s live '
      . 'status check. Needed because GLPI usually sits behind a TLS terminator, so the request '
      . 'arrives from the application server rather than the name the agent was given.', 'glpiosquery')
   . "</div>";
echo "</div>";

echo "<div class='col-md-6 mt-2'>";
echo "<label class='form-check form-switch'>";
echo "<input class='form-check-input' type='checkbox' name='compliance_tickets' value='1'"
   . (!empty($settings['compliance_tickets']) ? " checked" : "") . ">";
echo "<span class='form-check-label'>" . __('Open a ticket when a machine fails a compliance check', 'glpiosquery') . "</span>";
echo "</label>";
echo "<div class='form-text'>"
   . __('One open ticket per machine per check; a check that cannot be assessed never raises one.', 'glpiosquery')
   . "</div>";
echo "</div>";

echo "<div class='col-md-6 mt-2'>";
echo "<label class='form-check form-switch'>";
echo "<input class='form-check-input' type='checkbox' name='ticket_evidence' value='1'"
   . (!empty($settings['ticket_evidence']) ? " checked" : "") . ">";
echo "<span class='form-check-label'>"
   . __('Attach machine state to tickets automatically', 'glpiosquery') . "</span>";
echo "</label>";
echo "<div class='form-text'>"
   . __('When an asset is attached to a ticket, ask it for OS, uptime, disk, memory, top '
      . 'processes and who is logged in, and post the answers as one followup. Off by default: '
      . 'this collects a process list and the logged-in user without anyone asking.', 'glpiosquery')
   . "</div>";
echo "</div>";

echo "<div class='col-md-6 mt-2'>";
echo "<label class='form-check form-switch'>";
echo "<input class='form-check-input' type='checkbox' name='ticket_evidence_private' value='1'"
   . (!isset($settings['ticket_evidence_private']) || !empty($settings['ticket_evidence_private']) ? " checked" : "") . ">";
echo "<span class='form-check-label'>"
   . __('Keep the evidence followup private', 'glpiosquery') . "</span>";
echo "</label>";
echo "<div class='form-text'>"
   . __('A private followup is visible to technicians but not to the requester. Turning this '
      . 'off shows people the process list of their own machine.', 'glpiosquery')
   . "</div>";
echo "</div>";

echo "</form>";

// What the fleet is actually running — the question that matters once machines
// update themselves.
echo "<div class='row'>";
foreach (
    [
        'agent_version'   => __('Agent versions in the fleet', 'glpiosquery'),
        'osquery_version' => __('osquery versions in the fleet', 'glpiosquery'),
    ] as $column => $label
) {
    echo "<div class='col-md-6'>";
    echo "<h4 class='h5'>" . $label . "</h4>";
    echo "<table class='table table-sm'><tbody>";
    $spread = AgentUpdate::versionSpread($column);
    if ($spread === []) {
        echo "<tr><td class='text-muted'>" . __('No agents yet.', 'glpiosquery') . "</td></tr>";
    }
    foreach ($spread as $row) {
        echo "<tr><td><code>"
           . htmlspecialchars($row['version'] !== '' ? $row['version'] : __('unknown', 'glpiosquery'))
           . "</code></td><td class='text-end'>" . $row['cpt'] . "</td></tr>";
    }
    echo "</tbody></table>";
    echo "</div>";
}
echo "</div>";

echo "<h4 class='h5 mt-3'>" . __('Published packages', 'glpiosquery') . "</h4>";
echo "<table class='table table-sm'><thead><tr>"
   . "<th>" . __('Kind', 'glpiosquery') . "</th><th>" . __('Version') . "</th>"
   . "<th>" . __('Platform', 'glpiosquery') . "</th><th>" . __('Architecture', 'glpiosquery') . "</th>"
   . "<th>" . __('SHA-256', 'glpiosquery') . "</th><th></th></tr></thead><tbody>";
$has_package = false;
foreach (
    $DB->request([
        'FROM'  => AgentUpdate::PACKAGE_TABLE,
        'WHERE' => ['is_active' => 1],
        'ORDER' => ['kind', 'platform', 'arch'],
    ]) as $package
) {
    $has_package = true;
    echo "<tr><td>" . htmlspecialchars((string) $package['kind']) . "</td>";
    echo "<td>" . htmlspecialchars((string) $package['version']) . "</td>";
    echo "<td>" . htmlspecialchars((string) $package['platform']) . "</td>";
    echo "<td>" . htmlspecialchars((string) $package['arch']) . "</td>";
    echo "<td><code class='small'>" . htmlspecialchars(substr((string) $package['sha256'], 0, 16)) . "…</code></td>";
    echo "<td class='text-end'>";
    if ($can_edit) {
        echo "<form method='post' class='d-inline'>" . $csrf
           . "<button class='btn btn-sm btn-outline-danger' name='retire_package' value='"
           . (int) $package['id'] . "'>" . __('Withdraw', 'glpiosquery') . "</button></form>";
    }
    echo "</td></tr>";
}
if (!$has_package) {
    echo "<tr><td colspan='6' class='text-muted'>"
       . __('No packages published. Agents will be told there is nothing to install.', 'glpiosquery')
       . "</td></tr>";
}
echo "</tbody></table>";

// The checksum and size are the ones build.sh prints next to each archive, so
// publishing is a copy of that output rather than a second measurement that
// could disagree with the artifact.
echo "<form method='post' class='row g-2 align-items-end'>" . $csrf;
echo "<div class='col-auto'><label class='form-label small'>" . __('Kind', 'glpiosquery') . "</label>";
echo "<select name='pkg_kind' class='form-select form-select-sm'>"
   . "<option value='agent'>agent</option><option value='osquery'>osquery</option></select></div>";
echo "<div class='col-auto'><label class='form-label small'>" . __('Version') . "</label>"
   . "<input name='pkg_version' class='form-control form-control-sm' placeholder='1.0.1' size='8'></div>";
echo "<div class='col-auto'><label class='form-label small'>" . __('Platform', 'glpiosquery') . "</label>";
echo "<select name='pkg_platform' class='form-select form-select-sm'>"
   . "<option value='linux'>linux</option><option value='darwin'>darwin</option>"
   . "<option value='windows'>windows</option></select></div>";
echo "<div class='col-auto'><label class='form-label small'>" . __('Architecture', 'glpiosquery') . "</label>";
echo "<select name='pkg_arch' class='form-select form-select-sm'>"
   . "<option value='amd64'>amd64</option><option value='arm64'>arm64</option></select></div>";
echo "<div class='col-auto'><label class='form-label small'>" . __('Size (bytes)', 'glpiosquery') . "</label>"
   . "<input name='pkg_size' class='form-control form-control-sm' size='10'></div>";
echo "<div class='col-12'><label class='form-label small'>" . __('URL', 'glpiosquery') . "</label>"
   . "<input name='pkg_url' class='form-control form-control-sm' placeholder='https://…/glpi-osquery-agent_1.0.1_linux_amd64.tar.gz'></div>";
echo "<div class='col-12 col-md-9'><label class='form-label small'>" . __('SHA-256', 'glpiosquery') . "</label>"
   . "<input name='pkg_sha256' class='form-control form-control-sm font-monospace'></div>";
if ($can_edit) {
    echo "<div class='col-auto'><button class='btn btn-sm btn-primary' name='publish_package' value='1'>"
       . __('Publish', 'glpiosquery') . "</button></div>";
}
echo "</form>";

echo "</div></div>";

// ----------------------------------------------------------------- extensions
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
   . __('osquery extensions', 'glpiosquery') . "</h3></div>";
echo "<div class='card-body'>";
echo "<p class='text-muted'>"
   . __('An extension is a binary osqueryd runs as root to register extra tables. Publishing one '
      . 'here installs it on every agent in the scope you choose, outside the agent bundle so a '
      . 'self-update does not remove it. The tables it provides are discovered from the endpoints '
      . 'themselves and appear in the live-query console once at least one agent reports them.',
       'glpiosquery')
   . "</p>";

if (!Extension::canManage()) {
    // Shown, not hidden. An entity administrator seeing what their machines run
    // is useful; the point of the restriction is that they cannot change it.
    //
    // Both conditions are named because they fail for different people. A super
    // administrator hits the first one — the right is granted to nobody on
    // install, deliberately — and would otherwise read this as a claim that
    // they are not an administrator of the instance, which is not what stopped
    // them and not something they can act on.
    echo "<div class='alert alert-info py-2'>"
       . __('Read only. Publishing an extension needs the "Manage osquery extensions" right, '
          . 'which is granted to no profile on install, and a session that can see every entity.',
            'glpiosquery')
       . "</div>";
}

echo "<table class='table table-sm'><thead><tr>"
   . "<th>" . __('Name') . "</th><th>" . __('Entity') . "</th>"
   . "<th>" . __('Tables', 'glpiosquery') . "</th><th>" . __('Binaries', 'glpiosquery') . "</th>"
   . "<th>" . __('Installed', 'glpiosquery') . "</th><th></th></tr></thead><tbody>";

$extensions = Extension::all();
foreach ($extensions as $extension) {
    $tables = json_decode((string) ($extension['provided_tables'] ?? ''), true);
    $tables = is_array($tables) ? $tables : [];

    $binaries = 0;
    foreach (
        $DB->request([
            'FROM'  => AgentUpdate::PACKAGE_TABLE,
            'WHERE' => ['kind' => AgentUpdate::KIND_EXTENSION, 'name' => $extension['name'], 'is_active' => 1],
        ]) as $ignored
    ) {
        $binaries++;
    }

    $installed = 0;
    foreach ($DB->request(['FROM' => Node::TABLE, 'WHERE' => ['is_deleted' => 0]]) as $agent) {
        if (in_array((string) $extension['name'], Extension::installedOn($agent), true)) {
            $installed++;
        }
    }

    $scope = Dropdown::getDropdownName('glpi_entities', (int) $extension['entities_id']);
    if (!empty($extension['is_recursive'])) {
        $scope .= ' ' . __('(and below)', 'glpiosquery');
    }

    echo "<tr" . (empty($extension['is_active']) ? " class='text-muted'" : "") . ">";
    echo "<td><code>" . htmlspecialchars((string) $extension['name']) . "</code>";
    if (!empty($extension['label'])) {
        echo "<div class='small text-muted'>" . htmlspecialchars((string) $extension['label']) . "</div>";
    }
    if (empty($extension['is_active'])) {
        echo " <span class='badge bg-secondary'>" . __('Inactive', 'glpiosquery') . "</span>";
    }
    echo "</td>";
    echo "<td>" . htmlspecialchars($scope) . "</td>";
    echo "<td class='small'>"
       . ($tables === []
            ? "<span class='text-muted'>" . __('not discovered yet', 'glpiosquery') . "</span>"
            : htmlspecialchars(implode(', ', $tables)))
       . "</td>";
    echo "<td>" . $binaries . "</td>";
    echo "<td>" . $installed . "</td>";
    echo "<td class='text-end'>";
    if (Extension::canManage()) {
        echo "<form method='post' class='d-inline'>" . $csrf
           . "<button class='btn btn-sm btn-outline-danger' name='delete_extension' value='"
           . (int) $extension['id'] . "'>" . __('Remove', 'glpiosquery') . "</button></form>";
    }
    echo "</td></tr>";
}
if ($extensions === []) {
    echo "<tr><td colspan='6' class='text-muted'>"
       . __('No extensions published.', 'glpiosquery') . "</td></tr>";
}
echo "</tbody></table>";

if (Extension::canManage()) {
    echo "<h4 class='h5 mt-3'>" . __('Register an extension', 'glpiosquery') . "</h4>";
    echo "<form method='post' class='row g-2 align-items-end mb-4'>" . $csrf;
    echo "<div class='col-auto'><label class='form-label small'>" . __('Name') . "</label>"
       . "<input name='ext_name' class='form-control form-control-sm' placeholder='acme-inventory' size='16'></div>";
    echo "<div class='col-auto'><label class='form-label small'>" . __('Label', 'glpiosquery') . "</label>"
       . "<input name='ext_label' class='form-control form-control-sm' size='20'></div>";
    echo "<div class='col-auto'><label class='form-label small'>" . __('Entity') . "</label>";
    echo Entity::dropdown([
        'name'      => 'ext_entities_id',
        'value'     => 0,
        'display'   => false,
        'width'     => '200px',
    ]);
    echo "</div>";
    echo "<div class='col-auto'><label class='form-label small d-block'>&nbsp;</label>"
       . "<label class='form-check form-check-inline'><input type='checkbox' class='form-check-input' "
       . "name='ext_is_recursive' value='1' checked> " . __('and sub-entities', 'glpiosquery') . "</label>"
       . "<label class='form-check form-check-inline'><input type='checkbox' class='form-check-input' "
       . "name='ext_is_active' value='1' checked> " . __('Active') . "</label></div>";
    echo "<div class='col-12'><label class='form-label small'>" . __('Comments') . "</label>"
       . "<input name='ext_comment' class='form-control form-control-sm'></div>";
    echo "<div class='col-auto'><button class='btn btn-sm btn-primary' name='save_extension' value='1'>"
       . __('Save') . "</button></div>";
    echo "<div class='col-12'><p class='text-muted small mb-0'>"
       . __('Saving an existing name updates its scope. Removing an extension uninstalls it from '
          . 'every endpoint on their next check-in.', 'glpiosquery')
       . "</p></div>";
    echo "</form>";

    echo "<h4 class='h5 mt-3'>" . __('Publish a binary', 'glpiosquery') . "</h4>";
    echo "<form method='post' class='row g-2 align-items-end'>" . $csrf;
    echo "<div class='col-auto'><label class='form-label small'>" . __('Extension', 'glpiosquery') . "</label>";
    echo "<select name='extpkg_name' class='form-select form-select-sm'>";
    foreach ($extensions as $extension) {
        echo "<option value='" . htmlspecialchars((string) $extension['name']) . "'>"
           . htmlspecialchars((string) $extension['name']) . "</option>";
    }
    echo "</select></div>";
    echo "<div class='col-auto'><label class='form-label small'>" . __('Version') . "</label>"
       . "<input name='extpkg_version' class='form-control form-control-sm' placeholder='1.0.0' size='8'></div>";
    echo "<div class='col-auto'><label class='form-label small'>" . __('Platform', 'glpiosquery') . "</label>";
    echo "<select name='extpkg_platform' class='form-select form-select-sm'>"
       . "<option value='linux'>linux</option><option value='darwin'>darwin</option>"
       . "<option value='windows'>windows</option></select></div>";
    echo "<div class='col-auto'><label class='form-label small'>" . __('Architecture', 'glpiosquery') . "</label>";
    echo "<select name='extpkg_arch' class='form-select form-select-sm'>"
       . "<option value='amd64'>amd64</option><option value='arm64'>arm64</option></select></div>";
    echo "<div class='col-auto'><label class='form-label small'>" . __('Size (bytes)', 'glpiosquery') . "</label>"
       . "<input name='extpkg_size' class='form-control form-control-sm' size='10'></div>";
    echo "<div class='col-12'><label class='form-label small'>" . __('URL', 'glpiosquery') . "</label>"
       . "<input name='extpkg_url' class='form-control form-control-sm' placeholder='https://…/acme-inventory_1.0.0_linux_amd64.ext'></div>";
    echo "<div class='col-12 col-md-9'><label class='form-label small'>" . __('SHA-256', 'glpiosquery') . "</label>"
       . "<input name='extpkg_sha256' class='form-control form-control-sm font-monospace'></div>";
    echo "<div class='col-auto'><button class='btn btn-sm btn-primary' name='publish_extension' value='1'>"
       . __('Publish', 'glpiosquery') . "</button></div>";
    echo "<div class='col-12'><p class='text-muted small mb-0'>"
       . __('The URL must serve the extension executable itself, not an archive. The agent verifies '
          . 'the SHA-256 before installing and refuses a binary that does not match.', 'glpiosquery')
       . "</p></div>";
    echo "</form>";
}

echo "</div></div>";

// ------------------------------------------------------------------ endpoints
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
   . __('Agent endpoints', 'glpiosquery') . "</h3></div>";
echo "<div class='card-body'>";
echo "<p class='text-muted'>"
   . __('osquery 5.x will not connect over plain HTTP, and there is no longer an option to '
      . 'allow it. This GLPI must be reachable over HTTPS with a certificate the endpoint '
      . 'trusts.', 'glpiosquery')
   . "</p>";
echo "<table class='table table-sm'><tbody>";
foreach ([
    '--enroll_tls_endpoint'            => '/plugins/glpiosquery/front/enroll.php',
    '--config_tls_endpoint'            => '/plugins/glpiosquery/front/config.php',
    '--logger_tls_endpoint'            => '/plugins/glpiosquery/front/log.php',
    '--distributed_tls_read_endpoint'  => '/plugins/glpiosquery/front/read.php',
    '--distributed_tls_write_endpoint' => '/plugins/glpiosquery/front/write.php',
] as $flag => $path) {
    echo "<tr><td><code>" . htmlspecialchars($flag) . "</code></td>"
       . "<td><code>" . htmlspecialchars($path) . "</code></td></tr>";
}
echo "</tbody></table>";
echo "</div></div>";

echo "</div>";

Html::footer();
