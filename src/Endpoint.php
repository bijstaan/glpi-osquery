<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

/**
 * Shared plumbing for the osquery TLS remote endpoints.
 *
 * These are not ordinary GLPI pages: no session, no CSRF token, no HTML. They
 * are machine endpoints authenticated by an enrollment secret or a node key,
 * and every one of them is hit by the entire fleet on a timer, so they stay
 * deliberately thin.
 */
final class Endpoint
{
    /**
     * Decode the request body.
     *
     * osquery always POSTs JSON. Values are scrubbed of NUL bytes on the way
     * in: real captures contain them (system_info.cpu_brand arrives NUL-padded
     * on AMD hardware) and they will otherwise truncate or reject on insert.
     */
    public static function payload(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return [];
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return [];
        }

        return self::scrub($data);
    }

    /**
     * Recursively strip NUL bytes and normalise scalars to strings osquery's
     * own conventions expect.
     *
     * @param mixed $value
     * @return mixed
     */
    public static function scrub($value)
    {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $out[is_string($k) ? str_replace("\0", '', $k) : $k] = self::scrub($v);
            }
            return $out;
        }

        if (is_string($value)) {
            return trim(str_replace("\0", '', $value));
        }

        return $value;
    }

    /**
     * Send a JSON response and stop.
     *
     * Every osquery response may carry node_invalid; when true the agent throws
     * away its node key and re-enrols, which is how an operator revokes one.
     */
    public static function respond(array $data, int $code = 200): void
    {
        if (!headers_sent()) {
            http_response_code($code);
            header('Content-Type: application/json');
            header('Cache-Control: no-store');
            // Belt and braces for the one caller that is not osquery: a browser
            // pointed at an endpoint URL must read this as data, not sniff the
            // agent-supplied strings inside it back into markup.
            header('X-Content-Type-Options: nosniff');
        }
        echo json_encode($data);
        exit;
    }

    /**
     * The agent is unknown or revoked: tell it to start over.
     *
     * Answered with HTTP 200 deliberately. `node_invalid` is an application
     * level instruction that osquery only reads out of a *successful* response
     * — a non-200 status is treated as a transport failure, so the body is
     * never parsed and the agent retries the same dead credentials forever
     * instead of re-enrolling. Returning 401 here looks more correct and
     * quietly breaks the only recovery path a revoked agent has.
     */
    public static function nodeInvalid(): void
    {
        self::respond(['node_invalid' => true]);
    }

    /**
     * The address the endpoint is contacting us from.
     *
     * Proxy headers are honoured because these deployments sit behind a TLS
     * terminator by necessity — osquery will not talk to a plain-HTTP GLPI —
     * so REMOTE_ADDR is nearly always the proxy rather than the machine.
     */
    public static function remoteAddress(): string
    {
        foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'] as $header) {
            if (empty($_SERVER[$header])) {
                continue;
            }
            $candidate = trim(explode(',', (string) $_SERVER[$header])[0]);
            if ($candidate !== '') {
                return mb_substr($candidate, 0, 64);
            }
        }

        return mb_substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 64);
    }

    /**
     * Resolve the caller from its node key, or terminate with node_invalid.
     *
     * Also stamps last_seen, since this runs on every authenticated request and
     * is the cheapest honest liveness signal we have.
     */
    public static function requireAgent(array $payload): array
    {
        $node_key = (string) ($payload['node_key'] ?? '');
        if ($node_key === '') {
            self::nodeInvalid();
        }

        $agent = Node::byNodeKey($node_key);
        if ($agent === null) {
            self::nodeInvalid();
        }

        return $agent;
    }
}
