<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonGLPI;
use Session;

/**
 * Tools-menu entry for the fleet-wide live query console.
 *
 * As with Menu, the `: bool` return types are load-bearing — CommonGLPI
 * declares them, and a mismatch is a fatal error inside menu generation that
 * takes out every page in GLPI.
 */
class ConsoleMenu extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('osquery live query', 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-terminal-2';
    }

    public static function canView(): bool
    {
        return (bool) Session::haveRight('plugin_glpiosquery_livequery', READ);
    }

    public static function canCreate(): bool
    {
        return (bool) Session::haveRight('plugin_glpiosquery_livequery', UPDATE);
    }

    public static function getMenuContent()
    {
        if (!self::canView()) {
            return false;
        }

        // A GLPI menu section takes one class, so the saved query library hangs
        // off this entry as a sub-item rather than needing a section of its own.
        return [
            'title'   => self::getTypeName(),
            'page'    => '/plugins/glpiosquery/front/console.php',
            'icon'    => self::getIcon(),
            'options' => [
                'savedquery' => [
                    'title' => SavedQuery::getTypeName(2),
                    'page'  => '/plugins/glpiosquery/front/savedquery.php',
                    'icon'  => SavedQuery::getIcon(),
                    'links' => [
                        'search' => '/plugins/glpiosquery/front/savedquery.php',
                        'add'    => '/plugins/glpiosquery/front/savedquery.form.php',
                    ],
                ],
            ],
        ];
    }
}
