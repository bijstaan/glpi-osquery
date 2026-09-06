<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

/**
 * URLs for the plugin's own resources.
 *
 * GLPI 11 deprecated Plugin::getWebDir in favour of the plain `/plugins/` path,
 * but that path still has to be prefixed with root_doc so an installation in a
 * subdirectory works. Note that files under the plugin's `public/` directory
 * are served *without* the `public/` segment.
 */
final class Url
{
    public const KEY = 'glpiosquery';

    /**
     * Root-relative path, WITHOUT the root_doc prefix.
     *
     * This is what Html::css() and Html::script() want: they run the value
     * through Html::getPrefixedUrl(), which prepends root_doc unconditionally,
     * so handing them an already-prefixed URL yields `/glpi/glpi/...` on any
     * installation that lives in a subdirectory.
     */
    public static function path(string $path): string
    {
        return '/plugins/' . self::KEY . '/' . ltrim($path, '/');
    }

    /**
     * Absolute URL including root_doc — for anything fetched directly from
     * JavaScript, which does not go through GLPI's prefixing helpers.
     */
    public static function to(string $path): string
    {
        global $CFG_GLPI;

        return rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . self::path($path);
    }

    /**
     * Cache-busting version for a static asset under `public/`.
     *
     * Html::css()/Html::script() default to appending GLPI's own version, which
     * does not change when a plugin's JavaScript does — so browsers keep
     * serving a stale file indefinitely, and a shipped fix simply does not
     * reach anyone who already loaded the page. That failure is invisible from
     * the server: the code is correct, the tests pass, and only real users with
     * warm caches are broken.
     *
     * The file's modification time is used so every edit invalidates, without
     * needing to remember to bump a version by hand.
     */
    public static function assetVersion(string $path): string
    {
        $file = dirname(__DIR__) . '/public/' . ltrim($path, '/');
        $mtime = is_readable($file) ? (int) filemtime($file) : 0;

        return PLUGIN_GLPIOSQUERY_VERSION . ($mtime > 0 ? '.' . $mtime : '');
    }
}
