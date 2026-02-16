import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, results, target_info):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Calculate Stats
        total = len(results)
        passed = sum(1 for r in results if r['result'] == 'PASS')
        score = (passed / total * 100) if total > 0 else 0

        summary = {
            "target": target_info,
            "timestamp": timestamp,
            "score": f"{score:.2f}%",
            "passed": passed,
            "failed": total - passed
        }

        report = {"summary": summary, "results": results}

        # Save JSON
        json_path = os.path.join(self.output_dir, f"audit_{timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=4)

        # Save Text
        txt_path = os.path.join(self.output_dir, f"audit_{timestamp}.txt")
        with open(txt_path, 'w') as f:
            f.write(f"CIS AUDIT REPORT - {timestamp}\n")
            f.write(f"Score: {score:.2f}%\n")
            f.write("="*60 + "\n")
            for r in results:
                f.write(f"[{r['result']}] {r['id']} {r['title']}\n")
                for c in r['checks']:
                    f.write(f"   Cmd: {c['cmd'][:100]}...\n")
                    f.write(f"   Out: {c['output'][:200]}\n")
                f.write("-" * 40 + "\n")
        
        return txt_path