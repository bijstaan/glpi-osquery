// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
/* global $ */
/**
 * The osquery live-query console.
 *
 * Two modes share this code:
 *   global  — the Setup console, targeting the fleet by entity / group / platform
 *   device  — the tab on a Computer, targeting that one machine
 *
 * The editor is Monaco (which GLPI already ships) with a completion provider
 * built from the osquery schema catalogue: tables after FROM/JOIN, columns
 * after an alias dot, and upstream descriptions as hover documentation.
 */
window.GlpiOsquery = window.GlpiOsquery || {};

(function () {
    'use strict';

    // GLPI exposes these globally for translated strings; fall back so the
    // console still works if it is ever loaded on a page that has not.
    const __ = window.__ || ((s) => s);
    const sprintf = window.sprintf || function (fmt) {
        const args = Array.prototype.slice.call(arguments, 1);
        let i = 0;
        return String(fmt)
            .replace(/%(\d+)\$s/g, (m, n) => args[n - 1])
            .replace(/%s/g, () => args[i++]);
    };

    const SQL_KEYWORDS = [
        'SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'INNER JOIN', 'ON', 'AS',
        'AND', 'OR', 'NOT', 'IN', 'LIKE', 'GROUP BY', 'ORDER BY', 'HAVING',
        'LIMIT', 'DISTINCT', 'COUNT', 'SUM', 'MIN', 'MAX', 'AVG', 'CASE', 'WHEN',
        'THEN', 'ELSE', 'END', 'UNION', 'IS NULL', 'IS NOT NULL', 'DESC', 'ASC',
    ];

    function csrfToken() {
        return $('meta[property="glpi:csrf_token"]').attr('content') || '';
    }

    class Console {
        constructor(options) {
            this.opts = options;
            this.schema = { tables: [] };
            this.tablesByName = new Map();
            this.editor = null;
            this.campaignId = null;
            this.sinceId = 0;
            this.columns = [];
            this.rows = [];
            this.rowCount = 0;
            this.pollTimer = null;
            this.$root = $('#' + options.rootId);
        }

        async init() {
            await this.loadSchema();
            await this.buildEditor();
            this.bindControls();
            this.renderSchemaBrowser();
        }

        // ----------------------------------------------------------- schema

        async loadSchema() {
            const url = this.opts.endpoints.schema
                + (this.opts.platform ? '?platform=' + encodeURIComponent(this.opts.platform) : '');
            const res = await fetch(url, { credentials: 'same-origin' });
            this.schema = await res.json();
            this.tablesByName = new Map(this.schema.tables.map((t) => [t.name, t]));
        }

        /**
         * Tables named in the query, with their aliases.
         * Drives both `alias.` completion and the unqualified column list.
         */
        referencedTables(text) {
            const found = new Map();
            const re = /\b(?:from|join)\s+([a-z_][a-z0-9_]*)(?:\s+(?:as\s+)?([a-z_][a-z0-9_]*))?/gi;
            let m;
            while ((m = re.exec(text)) !== null) {
                const table = m[1];
                if (!this.tablesByName.has(table)) {
                    continue;
                }
                found.set(table, table);
                // Skip alias slots that are really the next keyword.
                if (m[2] && !/^(where|on|join|inner|left|group|order|limit|having|as|using)$/i.test(m[2])) {
                    found.set(m[2], table);
                }
            }
            return found;
        }

        tableSuggestion(table, range, monaco) {
            const platforms = (table.platforms || []).join(', ');
            const evented = table.evented
                ? '\n\n**Evented table** — only contains what osqueryd observed while it was '
                  + 'running. A machine that restarted recently will look empty.'
                : '';
            const extension = table.extension
                ? '\n\n**Provided by the `' + table.extension + '` extension** shipped with the GLPI '
                  + 'agent. A stock osqueryd does not have this table and will return nothing.'
                : '';
            return {
                label: { label: table.name, detail: '  ' + platforms },
                kind: monaco.languages.CompletionItemKind.Struct,
                insertText: table.name,
                detail: platforms,
                documentation: {
                    value: (table.description || '') + evented + extension
                        + '\n\n' + table.columns.length + ' columns',
                },
                range: range,
            };
        }

        columnSuggestion(column, table, range, monaco, prefix) {
            return {
                label: { label: column.name, detail: '  ' + column.type.toLowerCase() },
                kind: monaco.languages.CompletionItemKind.Field,
                insertText: (prefix || '') + column.name,
                detail: table.name + '.' + column.name,
                documentation: { value: column.description || '' },
                range: range,
            };
        }

        /**
         * Every column in the catalogue, built once and reused.
         *
         * There are a few thousand, and this runs on every keystroke, so the
         * objects are cached and only their range is updated per call.
         */
        allColumnSuggestions(monaco) {
            if (this._allColumns) {
                return this._allColumns;
            }

            // Grouped by column name rather than one entry per table.column.
            //
            // Names like `host`, `path` and `name` occur in dozens of tables, so
            // listing each occurrence separately fills the popup with rows that
            // look identical and say nothing. One entry per name, telling the
            // operator where it can be found, is far more use.
            const byName = new Map();
            for (const table of this.schema.tables) {
                for (const column of table.columns) {
                    let entry = byName.get(column.name);
                    if (!entry) {
                        entry = { type: column.type, tables: [], description: column.description || '' };
                        byName.set(column.name, entry);
                    }
                    entry.tables.push(table.name);
                    if (!entry.description && column.description) {
                        entry.description = column.description;
                    }
                }
            }

            const items = [];
            for (const [name, entry] of byName) {
                const where = entry.tables.length === 1
                    ? entry.tables[0]
                    : entry.tables.length + ' tables';

                items.push({
                    label: { label: name, detail: '  ' + where },
                    kind: monaco.languages.CompletionItemKind.Field,
                    insertText: name,
                    detail: name + ' — ' + entry.type.toLowerCase() + ' — ' + where,
                    documentation: {
                        value: (entry.description || '')
                             + '\n\nIn: ' + entry.tables.slice(0, 12).map((t) => '`' + t + '`').join(', ')
                             + (entry.tables.length > 12 ? ` and ${entry.tables.length - 12} more` : ''),
                    },
                    // Columns lead in this position: the caret is in the select
                    // list, and the operator is naming what they want back.
                    sortText: '1' + name,
                });
            }

            this._allColumns = items;

            return items;
        }

        provideCompletions(model, position, monaco) {
            const word = model.getWordUntilPosition(position);
            const range = {
                startLineNumber: position.lineNumber,
                endLineNumber: position.lineNumber,
                startColumn: word.startColumn,
                endColumn: word.endColumn,
            };

            const before = model.getValueInRange({
                startLineNumber: 1,
                startColumn: 1,
                endLineNumber: position.lineNumber,
                endColumn: position.column,
            });

            const suggestions = [];
            const refs = this.referencedTables(model.getValue());

            // `alias.` or `table.` — only that table's columns are relevant.
            const dotted = before.match(/([a-z_][a-z0-9_]*)\.\s*[a-z0-9_]*$/i);
            if (dotted) {
                const target = refs.get(dotted[1]) || (this.tablesByName.has(dotted[1]) ? dotted[1] : null);
                const table = target ? this.tablesByName.get(target) : null;
                if (table) {
                    for (const column of table.columns) {
                        suggestions.push(this.columnSuggestion(column, table, range, monaco));
                    }
                    return { suggestions };
                }
            }

            // Straight after FROM / JOIN, a table name is the only sensible thing.
            if (/\b(from|join)\s+[a-z0-9_]*$/i.test(before)) {
                for (const table of this.schema.tables) {
                    suggestions.push(this.tableSuggestion(table, range, monaco));
                }
                return { suggestions };
            }

            // Otherwise: columns first, then tables, then keywords.
            //
            // sortText fixes the order regardless of how Monaco scores the
            // fuzzy match, so the most relevant kind stays on top.
            const named = new Set(refs.values());

            if (named.size > 0) {
                // The query already names tables, so those columns are what the
                // operator is reaching for.
                for (const tableName of named) {
                    const table = this.tablesByName.get(tableName);
                    if (!table) {
                        continue;
                    }
                    for (const column of table.columns) {
                        const item = this.columnSuggestion(column, table, range, monaco);
                        item.sortText = '1' + column.name;
                        suggestions.push(item);
                    }
                }
            } else {
                // Nothing named yet — which is the *normal* state, because SQL
                // is written SELECT-first and the FROM clause does not exist
                // until later. Offering no columns here made the editor look
                // like it had no column completion at all, so every column in
                // the catalogue is offered instead, each labelled with the
                // table it belongs to. Monaco's fuzzy filter makes that usable,
                // and picking one tells the operator which table to select from.
                for (const item of this.allColumnSuggestions(monaco)) {
                    item.range = range;
                    suggestions.push(item);
                }
            }

            for (const table of this.schema.tables) {
                const item = this.tableSuggestion(table, range, monaco);
                item.sortText = '2' + table.name;
                suggestions.push(item);
            }

            for (const keyword of SQL_KEYWORDS) {
                suggestions.push({
                    label: keyword,
                    kind: monaco.languages.CompletionItemKind.Keyword,
                    insertText: keyword,
                    sortText: '4' + keyword,
                    range: range,
                });
            }

            return { suggestions };
        }

        // ----------------------------------------------------------- editor

        async buildEditor() {
            const wrapper = await window.GLPI.Monaco.createEditor(
                this.opts.editorId,
                'sql',
                this.opts.initialSql || 'SELECT * FROM system_info;',
                [],
                {
                    minimap: { enabled: false },
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    fontSize: 13,
                    padding: { top: 8, bottom: 8 },
                }
            );

            this.editor = wrapper.editor;

            // GLPI's wrapper registers a static completion list against a
            // randomly-named language clone. Reading the id back off the model
            // lets us attach a context-aware provider to that same clone
            // instead of replacing the whole editor.
            const monaco = window.monaco;
            const languageId = this.editor.getModel().getLanguageId();

            monaco.languages.registerCompletionItemProvider(languageId, {
                triggerCharacters: ['.', ' '],
                provideCompletionItems: (model, position) => this.provideCompletions(model, position, monaco),
            });

            this.editor.addCommand(
                monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter,
                () => this.run()
            );
        }

        // --------------------------------------------------------- controls

        bindControls() {
            this.$root.find('[data-osq-run]').on('click', () => this.run());
            this.$root.find('[data-osq-stop]').on('click', () => this.stopPolling(true));
            this.$root.find('[data-osq-export]').on('click', () => this.exportCsv());

            const saved = this.opts.savedQueries || [];
            this.$root.find('[data-osq-saved]').on('change', (e) => {
                const id = parseInt(e.target.value, 10);
                const query = saved.find((q) => q.id === id);
                this.$root.find('[data-osq-saved-description]').text(query ? query.description || '' : '');

                if (!query) {
                    this.savedQuery = null;
                    return;
                }

                // Remember the exact stored text. Running it untouched is
                // permitted with only the saved-query right; the moment it is
                // edited it becomes free-form SQL and needs the other right, so
                // the comparison has to be against what the server holds.
                this.savedQuery = query;
                if (this.editor) {
                    this.editor.setValue(query.sql);
                }
            });
        }

        /** The saved query id to send, or null if the editor no longer matches it. */
        activeSavedQueryId() {
            if (!this.savedQuery || !this.editor) {
                return null;
            }

            const current = this.editor.getValue().trim();

            return current === this.savedQuery.sql.trim() ? this.savedQuery.id : null;
        }

        /**
         * Export what is on screen.
         *
         * Deliberately exports the rows actually received, not a re-run of the
         * query: an export that quietly differs from what the operator was
         * looking at is worse than no export.
         */
        exportCsv() {
            if (!this.rows || this.rows.length === 0) {
                return;
            }

            const columns = ['agent'].concat(this.columns);
            const escape = (v) => {
                const s = v === undefined || v === null ? '' : String(v);
                return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
            };

            const lines = [columns.map(escape).join(',')];
            for (const row of this.rows) {
                lines.push(
                    columns
                        .map((c) => escape(c === 'agent' ? row.agent : row.data[c]))
                        .join(',')
                );
            }

            const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'osquery-results-' + (this.campaignId || 'export') + '.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        renderSchemaBrowser() {
            const $list = this.$root.find('[data-osq-schema-list]');
            const $filter = this.$root.find('[data-osq-schema-filter]');
            if (!$list.length) {
                return;
            }

            const draw = (needle) => {
                const lower = (needle || '').toLowerCase();
                const matches = this.schema.tables.filter(
                    (t) => !lower || t.name.includes(lower) || (t.description || '').toLowerCase().includes(lower)
                );
                $list.empty();
                matches.slice(0, 200).forEach((table) => {
                    const $item = $('<button type="button" class="list-group-item list-group-item-action py-1"></button>');
                    $item.append($('<code></code>').text(table.name));
                    if (table.evented) {
                        $item.append(' <span class="badge bg-orange-lt" title="Only holds events observed while osqueryd was running">evented</span>');
                    }
                    if (table.extension) {
                        $item.append(' <span class="badge bg-azure-lt" title="Provided by an extension shipped with the GLPI agent, not by stock osquery">ext</span>');
                    }
                    $item.attr('title', table.description || '');
                    $item.on('click', () => this.insertTable(table.name));
                    $list.append($item);
                });
                this.$root.find('[data-osq-schema-count]').text(matches.length);
            };

            $filter.on('input', () => draw($filter.val()));
            draw('');
        }

        insertTable(name) {
            if (!this.editor) {
                return;
            }
            const selection = this.editor.getSelection();
            this.editor.executeEdits('schema-browser', [{
                range: selection,
                text: name,
                forceMoveMarkers: true,
            }]);
            this.editor.focus();
        }

        targetPayload() {
            if (this.opts.mode === 'device') {
                return { items: this.opts.items || [] };
            }

            const val = (selector) => {
                const raw = this.$root.find(selector).val();
                if (!raw) {
                    return [];
                }
                return (Array.isArray(raw) ? raw : [raw]).map((v) => v).filter((v) => v !== '' && v !== '0');
            };

            return {
                entities: val('[data-osq-entities]'),
                groups: val('[data-osq-groups]'),
                platforms: val('[data-osq-platforms]'),
                online_only: this.$root.find('[data-osq-online]').is(':checked'),
            };
        }

        // -------------------------------------------------------- execution

        async run() {
            if (!this.editor) {
                return;
            }

            this.stopPolling(false);
            this.resetResults();

            const savedId = this.activeSavedQueryId();
            const payload = Object.assign(
                { sql: this.editor.getValue(), saved_query_id: savedId },
                this.targetPayload()
            );

            // Without the free-form right, an edited saved query cannot run —
            // say so here rather than letting the server answer with a 403 that
            // does not explain what changed.
            if (!savedId && this.opts.canRawSql === false) {
                this.setStatus('warning', __('You can run saved queries unchanged. Editing one makes it a '
                    + 'free-form query, which needs the free-form query right.'));
                return;
            }

            this.setStatus('info', __('Dispatching…'));

            let data;
            try {
                // The token MUST travel in the header, and the request must
                // declare itself as XHR to make GLPI read it there.
                //
                // Putting the token in the form body instead also passes, but
                // GLPI validates that path with preserve_token = false and so
                // *consumes* the token: the first query would run and every
                // one after it would 403 until the page was reloaded. The
                // header path is validated with preserve_token = true
                // precisely so a page can make repeated AJAX calls.
                const res = await fetch(this.opts.endpoints.launch, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Glpi-Csrf-Token': csrfToken(),
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    body: JSON.stringify(payload),
                });

                const body = await res.text();
                try {
                    data = JSON.parse(body);
                } catch (parseError) {
                    // An HTML body means GLPI answered with an error page
                    // before this endpoint ran — a rejected CSRF token, or an
                    // expired session. Both are fixed by reloading, and saying
                    // so is far more use than surfacing a JSON syntax error.
                    this.setStatus('danger', sprintf(
                        __('The server rejected the request (HTTP %s). Reload the page and try again — '
                         + 'this usually means the page has been open since before a sign-in, or the '
                         + 'browser is running a cached copy of this console.'),
                        res.status
                    ));
                    return;
                }

                if (!res.ok) {
                    this.setStatus('danger', data.error || __('The query was rejected.'));
                    return;
                }
            } catch (e) {
                this.setStatus('danger', String(e));
                return;
            }

            if (!data.campaign_id) {
                this.setStatus('warning', data.warning || __('No agents matched.'));
                return;
            }

            this.campaignId = data.campaign_id;
            this.sinceId = 0;

            let note = sprintf(
                __('Asking %1$s agents. They answer on their next check-in, within about %2$s seconds.'),
                data.targeted,
                data.check_in_interval
            );
            if (data.evented_tables && data.evented_tables.length) {
                note += ' ' + sprintf(
                    __('Note: %s only contains events recorded while osqueryd was running.'),
                    data.evented_tables.join(', ')
                );
            }
            this.setStatus('info', note);
            this.$root.find('[data-osq-stop]').prop('disabled', false);

            this.poll();
        }

        poll() {
            const url = this.opts.endpoints.results
                + '?campaign=' + encodeURIComponent(this.campaignId)
                + '&since=' + encodeURIComponent(this.sinceId);

            fetch(url, { credentials: 'same-origin' })
                .then((r) => r.json())
                .then((data) => {
                    if (data.error) {
                        this.setStatus('danger', data.error);
                        this.stopPolling(true);
                        return;
                    }

                    this.appendRows(data.rows);
                    this.sinceId = Math.max(this.sinceId, data.max_id || 0);
                    this.renderProgress(data);

                    if (data.complete) {
                        this.stopPolling(true, data);
                        return;
                    }

                    this.pollTimer = window.setTimeout(() => this.poll(), 1000);
                })
                .catch((e) => {
                    this.setStatus('danger', String(e));
                    this.stopPolling(true);
                });
        }

        stopPolling(finished, data) {
            if (this.pollTimer) {
                window.clearTimeout(this.pollTimer);
                this.pollTimer = null;
            }
            if (finished) {
                this.$root.find('[data-osq-stop]').prop('disabled', true);
            }
            if (finished && data) {
                this.renderSummary(data);
            }
        }

        // ---------------------------------------------------------- results

        resetResults() {
            this.columns = [];
            this.rows = [];
            this.rowCount = 0;
            this.$root.find('[data-osq-results] thead').empty();
            this.$root.find('[data-osq-results] tbody').empty();
            this.$root.find('[data-osq-errors]').empty().hide();
            this.$root.find('[data-osq-progress]').show();
        }

        appendRows(rows) {
            if (!rows || !rows.length) {
                return;
            }

            const $table = this.$root.find('[data-osq-results]');
            const $head = $table.find('thead');
            const $body = $table.find('tbody');

            // Columns are discovered from the data, because the operator's SQL
            // decides them and two agents can legitimately return different
            // shapes (a UNION, a platform-dependent column).
            rows.forEach((row) => {
                Object.keys(row.data).forEach((key) => {
                    if (!this.columns.includes(key)) {
                        this.columns.push(key);
                    }
                });
            });

            if ($head.find('tr').length === 0 || $head.find('th').length !== this.columns.length + 1) {
                $head.empty();
                const $tr = $('<tr></tr>');
                $tr.append($('<th></th>').text(__('Agent')));
                this.columns.forEach((c) => $tr.append($('<th></th>').text(c)));
                $head.append($tr);

                // Pad already-rendered rows so a column that only appears in a
                // later agent's results still lines up with its header.
                const columnCount = this.columns.length;
                $body.find('tr').each((index, element) => {
                    const $row = $(element);
                    for (let i = $row.find('td').length - 1; i < columnCount; i++) {
                        $row.append($('<td></td>').text(''));
                    }
                });
            }

            rows.forEach((row) => {
                this.rows.push(row);
                const $tr = $('<tr></tr>');
                $tr.append($('<td class="text-muted"></td>').text(row.agent));
                this.columns.forEach((c) => {
                    $tr.append($('<td></td>').text(row.data[c] !== undefined ? row.data[c] : ''));
                });
                $body.append($tr);
                this.rowCount++;
            });

            this.$root.find('[data-osq-rowcount]').text(this.rowCount);
            this.$root.find('[data-osq-export]').prop('disabled', this.rows.length === 0);
        }

        renderProgress(data) {
            const pct = data.total ? Math.round((data.answered / data.total) * 100) : 0;
            this.$root.find('[data-osq-bar]').css('width', pct + '%');
            this.$root.find('[data-osq-answered]').text(data.answered);
            this.$root.find('[data-osq-total]').text(data.total);
            this.$root.find('[data-osq-rowcount]').text(this.rowCount);

            if (data.errors && data.errors.length) {
                const $errors = this.$root.find('[data-osq-errors]');
                $errors.empty().show();
                $errors.append($('<div class="fw-bold"></div>').text(
                    sprintf(__('%s agents could not run the query'), data.errors.length)
                ));
                data.errors.forEach((err) => {
                    $errors.append(
                        $('<div class="small"></div>')
                            .append($('<code></code>').text(err.agent))
                            .append(' ')
                            .append($('<span></span>').text(err.message))
                    );
                });
            }
        }

        /**
         * The closing summary is deliberately explicit about non-responders.
         * "142 of 156 answered" is the honest result of a fleet query, and an
         * operator acting during an incident needs to know the other 14 were
         * never heard from rather than assume they are clean.
         */
        renderSummary(data) {
            const outstanding = data.outstanding || 0;
            let level = 'success';
            let text = sprintf(
                __('%1$s of %2$s agents answered — %3$s rows.'),
                data.answered, data.total, this.rowCount
            );

            if (outstanding > 0) {
                level = 'warning';
                text = sprintf(
                    __('%1$s of %2$s agents answered — %3$s rows. %4$s never responded before the time limit and are not represented here.'),
                    data.answered, data.total, this.rowCount, outstanding
                );
            }

            if (data.slowest && data.slowest.wall_time_ms > 1000) {
                text += ' ' + sprintf(
                    __('Slowest was %1$s at %2$s ms.'),
                    data.slowest.agent, data.slowest.wall_time_ms
                );
            }

            this.setStatus(level, text);
            this.$root.find('[data-osq-bar]').css('width', '100%');
        }

        setStatus(level, message) {
            this.$root.find('[data-osq-status]')
                .removeClass('alert-info alert-success alert-warning alert-danger')
                .addClass('alert-' + level)
                .text(message)
                .show();
        }
    }

    window.GlpiOsquery.Console = Console;
    window.GlpiOsquery.start = function (options) {
        const c = new Console(options);
        c.init();
        return c;
    };
})();
