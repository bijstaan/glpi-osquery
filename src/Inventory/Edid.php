<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery\Inventory;

/**
 * EDID parser.
 *
 * osquery has no monitor table on Windows or Linux, but the raw EDID block is
 * readable on both — from the registry under
 * `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\...\Device Parameters\EDID` on
 * Windows, and from `/sys/class/drm/*​/edid` on Linux. Decoding it here is what
 * lets those platforms report monitors at all, which is otherwise a straight
 * regression against GLPI Agent.
 *
 * Structure (VESA E-EDID 1.3/1.4, first 128-byte block):
 *
 *   0..7    fixed header 00 FF FF FF FF FF FF 00
 *   8..9    manufacturer id — three 5-bit letters, big-endian, 'A' = 1
 *   10..11  product code, little-endian
 *   12..15  serial number, little-endian
 *   16      manufacture week
 *   17      manufacture year, offset from 1990
 *   54..125 four 18-byte descriptors; tag 0xFC = model name, 0xFF = serial text
 */
final class Edid
{
    /**
     * @param string $raw hex string (as the registry table returns it) or raw bytes
     * @return array<string,mixed>|null null when this is not a usable EDID block
     */
    public static function parse(string $raw): ?array
    {
        $bytes = self::toBytes($raw);
        if ($bytes === null) {
            return null;
        }

        $out = [
            'manufacturer' => self::manufacturer($bytes),
            'product_code' => sprintf('%04X', $bytes[10] | ($bytes[11] << 8)),
            'serial'       => '',
            'alt_serial'   => '',
            'name'         => '',
            'date'         => '',
            'edid_version' => sprintf('%d.%d', $bytes[18], $bytes[19]),
            'digital'      => ($bytes[20] & 0x80) === 0x80,
            'interface'    => '',
            'size_inches'  => 0.0,
            'resolution'   => '',
        ];

        $numeric = $bytes[12] | ($bytes[13] << 8) | ($bytes[14] << 16) | ($bytes[15] << 24);
        if ($numeric > 0) {
            $out['serial'] = (string) $numeric;
        }

        // Year 0 means unspecified; a week of 0xFF marks the "model year" form.
        $year = $bytes[17];
        if ($year > 0) {
            $out['date'] = sprintf('%04d-01-01', 1990 + $year);
            $out['year'] = 1990 + $year;
            if ($bytes[16] > 0 && $bytes[16] <= 54) {
                $out['week'] = $bytes[16];
            }
        }

        // Digital interface type, defined from EDID 1.4 onwards. On Windows —
        // where the connector cannot be read from a sysfs path — this is the
        // only clue as to how the panel is attached.
        if ($out['digital'] && $bytes[18] >= 1 && $bytes[19] >= 4) {
            $out['interface'] = match ($bytes[20] & 0x0F) {
                1       => 'dvi',
                2, 3    => 'hdmi',
                4       => 'mddi',
                5       => 'displayport',
                default => '',
            };
        }

        // Text descriptors only ever live in the base block.
        foreach ([54, 72, 90, 108] as $offset) {
            if ($offset + 18 > count($bytes)) {
                break;
            }
            if ($bytes[$offset] !== 0 || $bytes[$offset + 1] !== 0 || $bytes[$offset + 2] !== 0) {
                continue; // a detailed timing, handled below
            }

            $text = self::descriptorText($bytes, $offset);
            if ($text === '') {
                continue;
            }

            if ($bytes[$offset + 3] === 0xFC) {
                $out['name'] = $text;
            } elseif ($bytes[$offset + 3] === 0xFF) {
                // A printed serial is what an engineer can read off the case, so
                // it takes precedence; the numeric one is kept alongside rather
                // than discarded.
                $out['alt_serial'] = $out['serial'];
                $out['serial'] = $text;
            }
        }

        // The largest detailed timing across *every* block is the panel's real
        // maximum. Reading only the base block's first descriptor is wrong on
        // high-resolution displays: their native timing does not fit the base
        // block's constraints and lives in a CTA-861 extension instead, leaving
        // a lesser mode in the slot most parsers look at. Measured on a
        // 5120x1440 panel that advertises 3840x1080 first.
        $best_pixels = 0;
        foreach (self::detailedTimings($bytes) as $timing) {
            if ($timing['pixels'] > $best_pixels) {
                $best_pixels = $timing['pixels'];
                $out['resolution'] = $timing['resolution'];
            }
            // Physical size is a property of the panel, so take the first
            // descriptor that states one regardless of which mode won.
            if ($out['size_inches'] <= 0 && $timing['diagonal_mm'] > 0) {
                $out['size_inches'] = round($timing['diagonal_mm'] / 25.4, 1);
            }
        }

        // Fall back to the coarse cm figures in the base block when the detailed
        // timing descriptor carried no physical size.
        if ($out['size_inches'] <= 0 && $bytes[21] > 0 && $bytes[22] > 0) {
            $diagonal_cm = sqrt(($bytes[21] ** 2) + ($bytes[22] ** 2));
            $out['size_inches'] = round($diagonal_cm / 2.54, 1);
        }

        return $out;
    }

    /**
     * Every detailed timing descriptor in the block, base and extensions.
     *
     * Extension blocks are 128 bytes each. A CTA-861 block (tag 0x02) puts its
     * descriptors at the offset named in byte 2; other extension types are
     * skipped rather than guessed at.
     *
     * @param array<int,int> $bytes
     * @return array<int,array{resolution:string,diagonal_mm:float,pixels:int}>
     */
    private static function detailedTimings(array $bytes): array
    {
        $out = [];
        $total = count($bytes);

        foreach ([54, 72, 90, 108] as $offset) {
            if ($offset + 18 <= $total && !self::isTextDescriptor($bytes, $offset)) {
                $out[] = self::detailedTiming($bytes, $offset);
            }
        }

        $extensions = (int) floor($total / 128) - 1;
        for ($block = 1; $block <= $extensions; $block++) {
            $base = $block * 128;
            if ($base + 128 > $total || ($bytes[$base] ?? 0) !== 0x02) {
                continue;
            }

            $start = $bytes[$base + 2] ?? 0;
            if ($start < 4) {
                continue; // 0 means no detailed timings in this block
            }

            for ($offset = $base + $start; $offset + 18 <= $base + 127; $offset += 18) {
                // A zero pixel clock marks the end of the descriptor list.
                if (($bytes[$offset] | ($bytes[$offset + 1] << 8)) === 0) {
                    break;
                }
                $out[] = self::detailedTiming($bytes, $offset);
            }
        }

        return $out;
    }

    /** @param array<int,int> $bytes */
    private static function isTextDescriptor(array $bytes, int $offset): bool
    {
        return $bytes[$offset] === 0 && $bytes[$offset + 1] === 0 && $bytes[$offset + 2] === 0;
    }

    /**
     * Decode a detailed timing descriptor: resolution and panel size.
     *
     * Both are split across nibbles — the high bits of the active pixel counts
     * and of the millimetre dimensions live in a shared byte — which is why
     * this cannot just read the low bytes.
     *
     * @param array<int,int> $bytes
     * @return array{resolution:string,diagonal_mm:float,pixels:int}
     */
    private static function detailedTiming(array $bytes, int $o): array
    {
        $h_active = $bytes[$o + 2] | (($bytes[$o + 4] & 0xF0) << 4);
        $v_active = $bytes[$o + 5] | (($bytes[$o + 7] & 0xF0) << 4);

        $h_mm = $bytes[$o + 12] | (($bytes[$o + 14] & 0xF0) << 4);
        $v_mm = $bytes[$o + 13] | (($bytes[$o + 14] & 0x0F) << 8);

        return [
            'resolution'  => ($h_active > 0 && $v_active > 0) ? $h_active . 'x' . $v_active : '',
            'diagonal_mm' => ($h_mm > 0 && $v_mm > 0) ? sqrt(($h_mm ** 2) + ($v_mm ** 2)) : 0.0,
            'pixels'      => $h_active * $v_active,
        ];
    }

    /**
     * Which physical port a monitor is attached to, from the sysfs path.
     *
     * On Linux the connector is right there in the path
     * (/sys/class/drm/card1-DP-2/edid), which is more trustworthy than the
     * EDID's own interface byte — that describes what the panel supports, not
     * what it is currently plugged into.
     *
     * @return array{port:string,kind:string} kind is displayport|hdmi|dvi|vga|''
     */
    public static function connector(string $path): array
    {
        // .../card1-DP-2/edid -> card1-DP-2 -> DP-2
        $dir = basename(dirname($path));
        $name = preg_replace('/^card\d+-/', '', $dir) ?? $dir;

        if ($name === '' || $name === $dir && !str_contains($dir, '-')) {
            return ['port' => '', 'kind' => ''];
        }

        $kind = match (true) {
            (bool) preg_match('/^(e?DP)/i', $name)   => 'displayport',
            (bool) preg_match('/^HDMI/i', $name)     => 'hdmi',
            (bool) preg_match('/^DVI/i', $name)      => 'dvi',
            (bool) preg_match('/^(VGA|SVIDEO)/i', $name) => 'vga',
            default                                  => '',
        };

        return ['port' => $name, 'kind' => $kind];
    }

    /** @return array<int,int>|null */
    private static function toBytes(string $raw): ?array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }

        // The registry table hands back hex; a file read hands back bytes.
        if (preg_match('/^[0-9A-Fa-f\s]+$/', $raw) === 1 && strlen(preg_replace('/\s+/', '', $raw) ?? '') >= 256) {
            $binary = @hex2bin(strtolower(preg_replace('/\s+/', '', $raw) ?? ''));
            if ($binary === false) {
                return null;
            }
        } else {
            $binary = $raw;
        }

        if (strlen($binary) < 128) {
            return null;
        }

        $bytes = array_values(unpack('C*', $binary) ?: []);

        // Reject anything without the fixed header rather than emitting a
        // monitor assembled from unrelated bytes.
        $header = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        for ($i = 0; $i < 8; $i++) {
            if (($bytes[$i] ?? null) !== $header[$i]) {
                return null;
            }
        }

        return $bytes;
    }

    /** @param array<int,int> $bytes */
    private static function manufacturer(array $bytes): string
    {
        $packed = ($bytes[8] << 8) | $bytes[9];

        $letters = '';
        foreach ([10, 5, 0] as $shift) {
            $value = ($packed >> $shift) & 0x1F;
            if ($value < 1 || $value > 26) {
                return '';
            }
            $letters .= chr(ord('A') + $value - 1);
        }

        return $letters;
    }

    /** @param array<int,int> $bytes */
    private static function descriptorText(array $bytes, int $offset): string
    {
        $text = '';
        for ($i = $offset + 5; $i < $offset + 18; $i++) {
            $char = $bytes[$i] ?? 0x0A;
            if ($char === 0x0A) { // descriptors are newline-terminated, space-padded
                break;
            }
            $text .= chr($char);
        }

        return trim($text);
    }
}
