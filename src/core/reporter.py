import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Reporter:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, results, target_info):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Stats Calculation
        total_rules = len(results)
        manual = sum(1 for r in results if r['result'] == 'MANUAL')
        automated = total_rules - manual
        
        passed = sum(1 for r in results if r['result'] == 'PASS')
        failed = sum(1 for r in results if r['result'] == 'FAIL')
        skipped = sum(1 for r in results if r['result'] == 'SKIPPED')
        errors = sum(1 for r in results if r['result'] == 'ERROR')
        evaluated = passed + failed
        coverage = (evaluated / total_rules * 100) if total_rules else 0
        
        # Unknown, skipped and error outcomes are not compliance verdicts.
        score = (passed / evaluated * 100) if evaluated else None
        score_label = f'{score:.2f}%' if score is not None else 'N/A'

        # --- CLEANER TERMINAL SUMMARY ---
        print("\n" + "="*60)
        print(f"   COMPLIANCE REPORT SUMMARY")
        print("="*60)
        print(f"   Target System:   {target_info}")
        print(f"   Total Checklist: {total_rules}")
        print("-" * 30)
        print(f"   Automated:       {automated}")
        print(f"   Manual review:   {manual}")
        print("-" * 30)
        print(f"   Passed:          {passed}")
        print(f"   Failed:          {failed}")
        print(f"   Skipped:         {skipped}")
        print(f"   Errors:          {errors}")
        print(f"   Evaluated coverage: {coverage:.2f}%")
        print("="*60)
        print(f"   COMPLIANCE SCORE: {score_label} (Evaluated Only)")
        print("="*60 + "\n")

        summary = {
            "target": target_info,
            "timestamp": timestamp,
            "score": score_label,
            "coverage": f"{coverage:.2f}%",
            "stats": {
                "total": total_rules,
                "automated": automated,
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
            f.write(f"Score: {score_label} (of {evaluated} evaluated controls)\n")
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