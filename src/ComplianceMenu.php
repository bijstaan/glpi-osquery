<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonGLPI;
use Session;

/** Administration-menu entry for the compliance view. */
class ComplianceMenu extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('osquery compliance', 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-shield-check';
    }

    public static function canView(): bool
    {
        return (bool) Session::haveRight(Agent::$rightname, READ);
    }

    public static function canCreate(): bool
    {
        return false;
    }

    public static function getMenuContent()
    {
        if (!self::canView()) {
            return false;
        }

        return [
            'title' => self::getTypeName(),
            'page'  => '/plugins/glpiosquery/front/compliance.php',
            'icon'  => self::getIcon(),
        ];
    }
}
