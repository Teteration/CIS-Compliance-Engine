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
        
        # Score based only on AUTOMATED checks
        score = (passed / automated * 100) if automated > 0 else 0

        # --- CLEANER TERMINAL SUMMARY ---
        print("\n" + "="*60)
        print(f"   COMPLIANCE REPORT SUMMARY")
        print("="*60)
        print(f"   Target System:   {target_info}")
        print(f"   Total Checklist: {total_rules}")
        print("-" * 30)
        print(f"   Automated:       {automated}")
        print(f"   Manual (Skipped):{manual}")
        print("-" * 30)
        print(f"   Passed:          {passed}")
        print(f"   Failed:          {failed}")
        print("="*60)
        print(f"   COMPLIANCE SCORE: {score:.2f}% (Automated Only)")
        print("="*60 + "\n")

        summary = {
            "target": target_info,
            "timestamp": timestamp,
            "score": f"{score:.2f}%",
            "stats": {
                "total": total_rules,
                "automated": automated,
                "manual": manual,
                "passed": passed,
                "failed": failed
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
            f.write(f"Score: {score:.2f}% (of {automated} automated checks)\n")
            f.write("="*60 + "\n")
            
            for r in results:
                # Format: [PASS] 1.1 Title
                f.write(f"[{r['result']}] {r['id']} {r['title']}\n")
                
                if r['result'] == 'MANUAL':
                    f.write("   Note: Manual verification required.\n")
                
                for c in r['checks']:
                    # Only write command details if it Failed or Error
                    if r['result'] in ['FAIL', 'ERROR']:
                        f.write(f"   Cmd: {c['cmd'][:100]}...\n")
                        f.write(f"   Out: {str(c['output']).strip()}\n")
                f.write("-" * 40 + "\n")
        
        return txt_path