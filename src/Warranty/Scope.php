<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery\Warranty;

use CommonDBTM;
use DBmysql;
use Glpi\DBAL\QueryExpression;

/**
 * Which assets this plugin checks warranties for, and what it knows about them.
 *
 * **The only plugin-specific file in this subsystem.** Everything else under
 * `Warranty/` is identical between glpi-osquery and glpi-netscan and is kept
 * in step by `tools/sync-warranty.sh`; this is the seam, because the two
 * plugins own different parts of an estate.
 *
 * Here that is the machines an osquery agent produced: the plugin inventoried
 * them, so it knows their serials are real and it is not reaching across into
 * assets another tool is responsible for. A Computer someone typed in by hand,
 * or that arrived from a different inventory source, is left alone by the cron
 * — though the tab on the asset will still look one up on request, because an
 * operator asking a direct question is a different thing from a scheduled job
 * deciding on its own to send a serial to a vendor.
 */
final class Scope
{
    /** The itemtypes an osquery agent can produce. */
    public const ITEMTYPES = ['Computer'];

    /**
     * Assets due for a lookup, oldest schedule first.
     *
     * Never-checked assets come first so a fresh install fills in from nothing
     * rather than re-checking the same few every run.
     *
     * @return array<int,array{itemtype:string,items_id:int}>
     */
    public static function due(int $limit): array
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!$DB->tableExists('glpi_plugin_glpiosquery_agents') || !$DB->tableExists(Record::TABLE)) {
            return [];
        }

        $out = [];

        foreach ($DB->request(self::dueCriteria($limit)) as $row) {
            $out[] = [
                'itemtype' => (string) $row['itemtype'],
                'items_id' => (int) $row['items_id'],
            ];
        }

        return $out;
    }

    /**
     * The query behind {@see due()}, separated so it can be built and run
     * against a scratch table without installing anything.
     *
     * @return array<string,mixed>
     */
    public static function dueCriteria(int $limit): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $agents = 'glpi_plugin_glpiosquery_agents';

        return [
            'SELECT'    => [
                $agents . '.itemtype AS itemtype',
                $agents . '.items_id AS items_id',
            ],
            'DISTINCT'  => true,
            'FROM'      => $agents,
            'LEFT JOIN' => [
                Record::TABLE => [
                    'ON' => [
                        Record::TABLE => 'items_id',
                        $agents       => 'items_id',
                        [
                            'AND' => [
                                Record::TABLE . '.itemtype' => new QueryExpression(
                                    $DB->quoteName($agents . '.itemtype')
                                ),
                            ],
                        ],
                    ],
                ],
            ],
            'WHERE'     => [
                $agents . '.is_deleted' => 0,
                $agents . '.itemtype'   => self::ITEMTYPES,
                ['NOT' => [$agents . '.items_id' => null]],
                [$agents . '.items_id'  => ['>', 0]],
                'OR' => [
                    [Record::TABLE . '.id'            => null],
                    [Record::TABLE . '.next_check_at' => null],
                    [Record::TABLE . '.next_check_at' => ['<=', new QueryExpression('NOW()')]],
                ],
            ],
            'ORDER'     => [
                new QueryExpression($DB->quoteName(Record::TABLE . '.next_check_at') . ' IS NULL DESC'),
                Record::TABLE . '.next_check_at ASC',
            ],
            'LIMIT'     => max(1, $limit),
        ];
    }

    /**
     * Everything a vendor might need about one asset.
     *
     * Returns null when the asset is gone, deleted, a template, or has nothing
     * that could be a serial — all of which are ordinary states, not errors.
     */
    public static function subjectFor(string $itemtype, int $items_id, ?array $settings = null): ?Subject
    {
        $item = getItemForItemtype($itemtype);

        if (!$item instanceof CommonDBTM || !$item->getFromDB($items_id)) {
            return null;
        }

        if (!empty($item->fields['is_deleted']) || !empty($item->fields['is_template'])) {
            return null;
        }

        $serial = trim((string) ($item->fields['serial'] ?? ''));
        if ($serial === '') {
            return null;
        }

        $settings ??= Settings::all();

        [$model, $part_number] = self::model($itemtype, $item);

        $subject = new Subject(
            itemtype: $itemtype,
            items_id: $items_id,
            serial: $serial,
            manufacturer: self::dropdownName('glpi_manufacturers', (int) ($item->fields['manufacturers_id'] ?? 0)),
            model: $model,
            part_number: $part_number,
            country: (string) ($settings['warranty_default_country'] ?? ''),
            name: (string) ($item->fields['name'] ?? '')
        );

        return $subject->isLookupable() ? $subject : null;
    }

    /**
     * The asset's model name and its product number.
     *
     * The product number is the field HP and HPE need and the one Lenovo uses
     * to disambiguate a repeated serial. GLPI keeps it on the model dropdown
     * rather than on the asset, and no inventory source fills it in, so in
     * practice it is there only where somebody has curated the model list —
     * which is exactly why the lookups degrade gracefully without it.
     *
     * @return array{0:string,1:string}
     */
    private static function model(string $itemtype, CommonDBTM $item): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $foreign = strtolower($itemtype) . 'models_id';
        $table   = 'glpi_' . strtolower($itemtype) . 'models';

        $models_id = (int) ($item->fields[$foreign] ?? 0);

        if ($models_id <= 0 || !$DB->tableExists($table)) {
            return ['', ''];
        }

        foreach (
            $DB->request([
                'SELECT' => ['name', 'product_number'],
                'FROM'   => $table,
                'WHERE'  => ['id' => $models_id],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return [
                trim((string) ($row['name'] ?? '')),
                trim((string) ($row['product_number'] ?? '')),
            ];
        }

        return ['', ''];
    }

    private static function dropdownName(string $table, int $id): string
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($id <= 0) {
            return '';
        }

        foreach (
            $DB->request([
                'SELECT' => ['name'],
                'FROM'   => $table,
                'WHERE'  => ['id' => $id],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return trim((string) $row['name']);
        }

        return '';
    }

    /** Is this asset one the scheduled sync is responsible for? */
    public static function covers(string $itemtype, int $items_id): bool
    {
        /** @var DBmysql $DB */
        global $DB;

        $agents = 'glpi_plugin_glpiosquery_agents';

        if (!in_array($itemtype, self::ITEMTYPES, true) || !$DB->tableExists($agents)) {
            return false;
        }

        return countElementsInTable($agents, [
            'itemtype'   => $itemtype,
            'items_id'   => $items_id,
            'is_deleted' => 0,
        ]) > 0;
    }
}
