import json
import os
import logging
import html
from datetime import datetime
from colorama import Fore, Style

logger = logging.getLogger(__name__)

class Reporter:
    @staticmethod
    def _single_line_values(value):
        """Copy report data with embedded line endings flattened for display."""
        if isinstance(value, str):
            return value.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
        if isinstance(value, dict):
            return {key: Reporter._single_line_values(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [Reporter._single_line_values(item) for item in value]
        return value

    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    @staticmethod
    def _html(value):
        return html.escape(str(value), quote=True)

    def _write_html_report(self, path, report):
        summary = report['summary']
        stats = summary['stats']
        database = summary['database']
        benchmark = summary['benchmark']
        cards = [('PASS', stats['passed']), ('FAIL', stats['failed']),
                 ('ERROR', stats['errors']), ('SKIPPED', stats['skipped']),
                 ('MANUAL', stats['manual'])]
        card_html = ''.join(
            f'<div class="card {status.lower()}"><span>{status}</span><strong>{count}</strong></div>'
            for status, count in cards)
        rows = []
        for rule in report['results']:
            checks = rule.get('checks', [])
            evidence = ''.join(
                '<div class="check"><b>Check type:</b> ' + self._html(check.get('type', 'Unknown')) +
                '<pre><code>' + self._html(check.get('cmd', '')) + '</code></pre>' +
                '<b>Output:</b><pre>' + self._html(check.get('output', '')) + '</pre></div>'
                for check in checks) or '<p class="muted">No executable check was recorded.</p>'
            if rule.get('audit_text'):
                evidence += '<b>Audit procedure:</b><pre>' + self._html(rule['audit_text']) + '</pre>'
            status = self._html(rule['result'])
            searchable = ' '.join((rule['id'], rule['title'], rule['result'],
                                   rule.get('assessment_type', ''), rule.get('audit_text', ''))).lower()
            rows.append(
                f'<tr data-search="{self._html(searchable)}" data-status="{status}">'
                f'<td>{self._html(rule["id"])}</td>'
                f'<td><span class="badge {status.lower()}">{status}</span></td>'
                f'<td>{self._html(rule.get("assessment_type", "UNKNOWN"))}</td>'
                f'<td>{self._html(rule["title"])}</td>'
                f'<td><details><summary>View evidence ({len(checks)})</summary>{evidence}</details></td></tr>')
        metadata = [('Target', summary['target']), ('Database product', database.get('product', 'Unknown')),
                    ('Database name', database.get('name', 'Unknown')), ('Database version', database.get('version', 'Unknown')),
                    ('Benchmark', benchmark.get('name', 'Unknown')), ('Benchmark version', benchmark.get('version', 'Unknown')),
                    ('Benchmark file', benchmark.get('file', 'Unknown')),
                    ('Generated', summary['timestamp'])]
        metadata_html = ''.join(f'<div><dt>{self._html(label)}</dt><dd>{self._html(value)}</dd></div>'
                                for label, value in metadata)
        page = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CCE Compliance Report — {self._html(summary['timestamp'])}</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1020; --surface:#141b2d; --line:#28324c; --text:#e8edf7; --muted:#9aa8c3; --cyan:#47d8ff; --green:#51ef9a; --red:#ff657b; --magenta:#ef75ff; --yellow:#ffe65b; --blue:#6ca9ff; }}
* {{ box-sizing:border-box }} body {{ margin:0; background:linear-gradient(145deg,#0b1020,#111a30); color:var(--text); font:15px/1.5 Inter,ui-sans-serif,system-ui,sans-serif }}
.wrap {{ max-width:1500px; margin:auto; padding:32px 22px 56px }} header {{ border:1px solid var(--line); border-radius:16px; padding:28px; background:rgba(20,27,45,.9) }}
h1 {{ margin:0; font-size:clamp(1.7rem,4vw,2.6rem) }} h1 span {{ color:var(--cyan) }} h2 {{ margin:32px 0 14px; font-size:1.05rem; letter-spacing:.08em; color:var(--cyan) }}
.subtitle,.muted {{ color:var(--muted) }} .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); gap:12px; margin-top:20px }}
.card {{ border:1px solid var(--line); border-left:4px solid var(--muted); border-radius:10px; padding:12px 16px; background:#10172a }} .card span {{ display:block; color:var(--muted); font-size:.75rem; letter-spacing:.08em }} .card strong {{ font-size:1.7rem }}
.pass {{ border-color:var(--green)!important;color:var(--green) }} .fail {{ border-color:var(--red)!important;color:var(--red) }} .error {{ border-color:var(--magenta)!important;color:var(--magenta) }} .skipped {{ border-color:var(--blue)!important;color:var(--blue) }} .manual {{ border-color:var(--yellow)!important;color:var(--yellow) }}
.score {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(205px,1fr)); gap:12px }} .score div, .meta, .table-wrap {{ border:1px solid var(--line); border-radius:12px; background:var(--surface) }} .score div {{ padding:16px }} .score b {{ display:block; font-size:1.6rem; color:var(--cyan) }}
.meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:0; padding:8px }} .meta div {{ padding:10px 12px }} dt {{ color:var(--muted); font-size:.75rem }} dd {{ margin:3px 0 0; overflow-wrap:anywhere }}
.toolbar {{ display:flex; gap:10px; flex-wrap:wrap; margin:14px 0 }} input,button {{ background:#0d1425; border:1px solid var(--line); color:var(--text); border-radius:8px; padding:9px 11px }} input {{ flex:1; min-width:220px }} button {{ cursor:pointer }} button:hover {{ border-color:var(--cyan) }}
.table-wrap {{ overflow:auto }} table {{ width:100%; border-collapse:collapse; min-width:850px }} th,td {{ text-align:left; padding:13px 14px; border-bottom:1px solid var(--line); vertical-align:top }} th {{ position:sticky; top:0; background:#19233a; color:var(--muted); font-size:.75rem; letter-spacing:.06em }} tr:hover {{ background:#18223a }} .badge {{ display:inline-block; min-width:76px; text-align:center; border:1px solid; border-radius:999px; padding:2px 8px; font-size:.75rem; font-weight:700 }}
details summary {{ cursor:pointer; color:var(--cyan) }} .check {{ margin:12px 0; padding:10px; border:1px solid var(--line); border-radius:8px }} pre {{ margin:7px 0 12px; padding:10px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; background:#080d19; border-radius:7px; color:#d7e2f4 }} code {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace }} footer {{ color:var(--muted); margin-top:22px; font-size:.85rem }}
@media print {{ body {{ background:#fff; color:#111 }} .wrap {{ max-width:none;padding:0 }} header,.meta,.score,.table-wrap {{ background:#fff;border-color:#bbb }} .toolbar {{ display:none }} th {{ position:static;background:#eee }} pre {{ background:#f4f4f4;color:#111 }} }}
</style></head><body><main class="wrap"><header><h1><span>CCE</span> Compliance Report</h1><p class="subtitle">Generated {self._html(summary['timestamp'])} · Target: {self._html(summary['target'])}</p><div class="metrics">{card_html}</div></header>
<h2>ASSESSMENT SUMMARY</h2><section class="score"><div><span class="muted">Compliance score</span><b>{self._html(summary['score'])}</b><small>{stats['passed']} passed / {stats['evaluated']} evaluated</small></div><div><span class="muted">Evaluated coverage</span><b>{self._html(summary['coverage'])}</b><small>{stats['evaluated']} evaluated / {stats['total']} total</small></div><div><span class="muted">Automation completion</span><b>{self._html(summary['automation_completion'])}</b><small>{stats['automated']} declared automated controls</small></div></section><p class="subtitle">{self._html(summary['score_context'])} {self._html(summary['score_basis'])}</p>
<h2>TARGET & BENCHMARK</h2><dl class="meta">{metadata_html}</dl>
<h2>CONTROL RESULTS</h2><div class="toolbar"><input id="search" aria-label="Search controls" placeholder="Search ID, title, type, or status"><button type="button" data-filter="ALL">All</button><button type="button" data-filter="PASS">Pass</button><button type="button" data-filter="FAIL">Fail</button><button type="button" data-filter="ERROR">Error</button><button type="button" data-filter="SKIPPED">Skipped</button><button type="button" data-filter="MANUAL">Manual</button></div>
<div class="table-wrap"><table><thead><tr><th>ID</th><th>Status</th><th>Type</th><th>Title</th><th>Evidence</th></tr></thead><tbody id="rules">{''.join(rows)}</tbody></table></div>
<footer>Generated by CIS Compliance Engine. PASS/FAIL applies only to evaluated controls; review coverage, skipped controls, and evidence before making compliance decisions.</footer></main>
<script>const input=document.querySelector('#search');let filter='ALL';const apply=()=>document.querySelectorAll('#rules tr').forEach(row=>{{const hit=row.dataset.search.includes(input.value.toLowerCase());row.hidden=!(hit&&(filter==='ALL'||row.dataset.status===filter));}});input.addEventListener('input',apply);document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{{filter=button.dataset.filter;apply();}}));</script></body></html>'''
        with open(path, 'w', encoding='utf-8') as report_file:
            report_file.write(page)

    def generate(self, results, target_info, metadata=None):
        # Presentation only: never mutate the executable/cached audit commands.
        results = self._single_line_values(results)
        target_info = self._single_line_values(target_info)
        metadata = self._single_line_values(metadata or {})
        database = metadata.get('database', {})
        benchmark = metadata.get('benchmark', {})
        identity = {
            'Database product': database.get('product', 'Unknown'),
            'Database name': database.get('name', 'Unknown'),
            'Database version': database.get('version', 'Unknown'),
            'Benchmark': benchmark.get('name', 'Unknown'),
            'Benchmark version': benchmark.get('version', 'Unknown'),
            'Benchmark file': benchmark.get('file') or 'Unknown',
        }
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Stats Calculation
        total_rules = len(results)
        manual = sum(1 for r in results if r['result'] == 'MANUAL')
        automated = sum(r.get('assessment_type') == 'AUTOMATED' for r in results)
        declared_manual = sum(r.get('assessment_type') == 'MANUAL' for r in results)
        unknown_type = total_rules - automated - declared_manual
        
        passed = sum(1 for r in results if r['result'] == 'PASS')
        failed = sum(1 for r in results if r['result'] == 'FAIL')
        skipped = sum(1 for r in results if r['result'] == 'SKIPPED')
        errors = sum(1 for r in results if r['result'] == 'ERROR')
        evaluated = passed + failed
        coverage = (evaluated / total_rules * 100) if total_rules else 0
        auto_evaluated = sum(r.get('assessment_type') == 'AUTOMATED' and r['result'] in ('PASS', 'FAIL') for r in results)
        completion = f'{auto_evaluated / automated * 100:.2f}%' if automated else 'N/A'
        
        # Unknown, skipped and error outcomes are not compliance verdicts.
        score = (passed / evaluated * 100) if evaluated else None
        score_label = f'{score:.2f}%' if score is not None else 'N/A'
        score_context = (
            f'Of {total_rules} total controls, {evaluated} were evaluated: '
            f'{passed} passed, {failed} failed; '
            f'{total_rules - evaluated} had no PASS/FAIL verdict '
            f'({errors} ERROR, {manual} MANUAL, {skipped} SKIPPED'
            + (f', {total_rules - evaluated - errors - manual - skipped} other outcomes'
               if total_rules - evaluated - errors - manual - skipped else '')
            + ').'
        )
        score_basis = (
            f'Score = {passed} passed / {evaluated} evaluated controls.'
            if evaluated else 'Score is N/A because no controls have a PASS/FAIL verdict.'
        )

        # Colors are presentation only; report data remains free of ANSI codes.
        def divider(character='='):
            print(Fore.LIGHTCYAN_EX + character * 60 + Style.RESET_ALL)

        def metric(label, value, color=Fore.LIGHTCYAN_EX):
            print(f'   {label + ":":<25} {color}{value}{Style.RESET_ALL}')

        print()
        divider()
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX + '   COMPLIANCE REPORT SUMMARY' + Style.RESET_ALL)
        divider()
        metric('Target System', target_info, Fore.WHITE)
        for label, value in identity.items():
            metric(label, value, Fore.WHITE)
        metric('Total Checklist', total_rules, Fore.WHITE)
        divider('-')
        metric('Automated', automated)
        metric('Source manual', declared_manual, Fore.LIGHTYELLOW_EX)
        metric('Unknown type', unknown_type, Fore.LIGHTYELLOW_EX if unknown_type else Fore.WHITE)
        metric('Automation completion', completion)
        metric('Manual review', manual, Fore.LIGHTYELLOW_EX)
        divider('-')
        metric('Passed', passed, Fore.LIGHTGREEN_EX)
        metric('Failed', failed, Fore.LIGHTRED_EX if failed else Fore.WHITE)
        metric('Skipped', skipped, Fore.LIGHTBLUE_EX if skipped else Fore.WHITE)
        metric('Errors', errors, Fore.LIGHTRED_EX if errors else Fore.WHITE)
        metric('Evaluated coverage', f'{coverage:.2f}%')
        divider()
        score_color = Fore.LIGHTYELLOW_EX if score is None else Fore.LIGHTGREEN_EX if score == 100 else Fore.LIGHTRED_EX
        metric('COMPLIANCE SCORE', score_label, Style.BRIGHT + score_color)
        print(f'   {score_context}')
        print(f'   {score_basis}')
        divider()
        print()

        summary = {
            "target": target_info,
            "database": database,
            "benchmark": benchmark,
            "timestamp": timestamp,
            "score": score_label,
            "score_context": score_context,
            "score_basis": score_basis,
            "coverage": f"{coverage:.2f}%",
            "automation_completion": completion,
            "stats": {
                "total": total_rules,
                "automated": automated,
                "declared_manual": declared_manual,
                "unknown_type": unknown_type,
                "manual": manual,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "errors": errors,
                "evaluated": evaluated
            }
        }

        report = {"summary": summary, "results": results}

        # JSON Report
        json_path = os.path.join(self.output_dir, f"audit_{timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=4)

        html_path = os.path.join(self.output_dir, f"audit_{timestamp}.html")
        self._write_html_report(html_path, report)
        return html_path