<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonGLPI;
use Session;

/**
 * Setup-menu entry (Setup → osquery Inventory).
 *
 * The `: bool` return types on canView/canCreate are load-bearing: CommonGLPI
 * declares them, and a signature mismatch here is a fatal compile error inside
 * menu generation — which takes out every HTML page in GLPI, not just this one.
 */
class Menu extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('osquery Inventory', 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-radar';
    }

    public static function canView(): bool
    {
        return (bool) Session::haveRight('config', READ);
    }

    public static function canCreate(): bool
    {
        return (bool) Session::haveRight('config', UPDATE);
    }

    /**
     * No getMenuContent().
     *
     * This class supplies the plugin's name and icon; it deliberately does not
     * register a Setup-menu entry. Setup > Plugins already links the settings
     * page, and a menu row pointing at the same page is a duplicate — with
     * several plugins installed, those duplicates are most of what is in the
     * Setup menu.
     */
}
