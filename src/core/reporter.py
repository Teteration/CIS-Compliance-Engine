import json
import os
import logging
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

        # Text Report
        txt_path = os.path.join(self.output_dir, f"audit_{timestamp}.txt")
        with open(txt_path, 'w') as f:
            f.write(f"CIS AUDIT REPORT - {timestamp}\n")
            f.write(f"Target: {target_info}\n")
            for label, value in identity.items():
                f.write(f'{label}: {value}\n')
            f.write(f"Score: {score_label}\n{score_context}\n{score_basis}\n")
            f.write(f"Evaluated coverage: {coverage:.2f}%\n")
            f.write("="*60 + "\n")
            
            for r in results:
                # Format: [PASS] 1.1 Title
                f.write(f"[{r['result']}] {r['id']} {r['title']}\n")
                
                if r['result'] == 'MANUAL':
                    f.write("   Note: Manual verification required.\n")
                    if r.get('audit_text'):
                        f.write(f"   Audit procedure: {r['audit_text']}\n")
                
                for c in r['checks']:
                    # Only write command details if it Failed or Error
                    if r['result'] in ['FAIL', 'ERROR', 'SKIPPED', 'MANUAL']:
                        f.write(f"   Cmd: {c['cmd'][:100]}...\n")
                        f.write(f"   Out: {str(c['output']).strip()}\n")
                f.write("-" * 40 + "\n")
        
        return txt_path