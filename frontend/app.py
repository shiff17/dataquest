#!/usr/bin/env python3
"""
Proactive Security Patch Automation Framework - Enhanced Backend
Hackathon Ready: ML + RL + EDA + CSV/JSON Output
"""

import os, time, json, random, logging, warnings
import requests, concurrent.futures
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Any

warnings.filterwarnings("ignore")

# ---------------- CONFIG ----------------
API_TIMEOUT = 15
MAX_THREADS = 5
CSV_FILENAME = "vulnerability_scan_results.csv"
JSON_FILENAME = "vulnerability_scan_results.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S"
)

# Import ML/EDA classes from your existing code
# (Keeping them unchanged but reused here)
# VulnerabilityEDA, PatchPrioritizationRL, EnhancedCVEChecker

# ============================================================================
# ENHANCED SECURITY SCANNER
# ============================================================================

class EnhancedSecurityScanner:
    """Main security scanner with EDA and RL capabilities"""

    def _init_(self):
        self.cve_checker = EnhancedCVEChecker()
        self.eda_engine = VulnerabilityEDA()
        self.rl_agent = PatchPrioritizationRL()
        self.results: List[Dict] = []

    def run_scan(self) -> Tuple[str, str]:
        """Run full security scan and return (CSV, JSON)"""
        logging.info("🛡 Starting Enhanced Proactive Security Scan")

        # STEP 1: Simulate installed software
        software = SAMPLE_INSTALLED_SOFTWARE
        logging.info(f"📦 Detected {len(software)} installed packages")

        # STEP 2: Parallel vulnerability check
        self.results = self._parallel_vulnerability_checks(software)

        # STEP 3: EDA
        eda_results = self.eda_engine.analyze_vulnerability_patterns(self.results)

        # STEP 4: RL recommendations
        rl_recs = self.rl_agent.get_patch_recommendations(self.results)

        # STEP 5: Save outputs
        csv_file = self._save_csv(self.results, rl_recs)
        json_file = self._save_json(self.results, rl_recs, eda_results)

        # STEP 6: Print summary
        self._summary(self.results, rl_recs)

        return csv_file, json_file

    def _parallel_vulnerability_checks(self, software: Dict) -> List[Dict]:
        """Run vulnerability checks in parallel threads"""
        logging.info("⚡ Checking vulnerabilities (parallel mode)...")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {
                executor.submit(self.cve_checker.enhanced_vulnerability_check, sw, meta["version"], meta): (sw, meta)
                for sw, meta in software.items()
            }

            for future in concurrent.futures.as_completed(futures):
                sw, meta = futures[future]
                try:
                    cve_info = future.result()
                    result = self._format_result(sw, meta, cve_info)
                    results.append(result)
                    logging.info(f"✅ {sw}: {cve_info['severity']} ({cve_info['cve_id']})")
                except Exception as e:
                    logging.error(f"❌ Error scanning {sw}: {e}")

        return results

    def _format_result(self, sw: str, meta: Dict, cve_info: Dict) -> Dict:
        """Format result dict with metadata + CVE info"""
        return {
            "software": sw,
            "version": meta["version"],
            "cve_id": cve_info.get("cve_id", "None"),
            "severity": cve_info.get("severity", "None"),
            "cvss_score": cve_info.get("cvss_score", 0),
            "ml_risk_score": cve_info.get("ml_risk_score", 0),
            "confidence_level": cve_info.get("confidence_level", 0.7),
            "description": cve_info.get("description", "N/A"),
            "status": "Vulnerable" if cve_info.get("severity") != "None" else "Safe",
            "scan_date": datetime.utcnow().isoformat(),
            "category": meta.get("category"),
            "criticality": meta.get("criticality"),
            "exposure": meta.get("exposure"),
            "users_affected": meta.get("users"),
            "uptime_requirement": meta.get("uptime_requirement"),
        }

    def _save_csv(self, results: List[Dict], rl_recs: List[Dict]) -> str:
        """Save results to CSV"""
        df = pd.DataFrame(results)

        # Attach RL recs if available
        rl_map = {r["software"]: r for r in rl_recs}
        df["rl_action"] = df["software"].map(lambda x: rl_map.get(x, {}).get("recommended_action", "monitor"))
        df["priority_score"] = df["software"].map(lambda x: rl_map.get(x, {}).get("priority_score", 0))
        df["ai_confidence"] = df["software"].map(lambda x: rl_map.get(x, {}).get("confidence", 0))

        df.to_csv(CSV_FILENAME, index=False)
        logging.info(f"💾 CSV saved: {CSV_FILENAME} ({len(df)} rows)")
        return CSV_FILENAME

    def _save_json(self, results: List[Dict], rl_recs: List[Dict], eda: Dict) -> str:
        """Save results + recs + EDA into JSON"""
        output = {
            "scan_time": datetime.utcnow().isoformat(),
            "results": results,
            "rl_recommendations": rl_recs,
            "eda_summary": eda,
        }
        with open(JSON_FILENAME, "w") as f:
            json.dump(output, f, indent=2)
        logging.info(f"💾 JSON saved: {JSON_FILENAME}")
        return JSON_FILENAME

    def _summary(self, results: List[Dict], rl_recs: List[Dict]):
        """ASCII summary for hackathon demo"""
        total = len(results)
        vuln = sum(1 for r in results if r["status"] == "Vulnerable")
        safe = total - vuln
        logging.info("=" * 50)
        logging.info(f"📊 SCAN SUMMARY: {total} total | 🚨 {vuln} vulnerable | ✅ {safe} safe")
        logging.info(f"🎯 Top Recommendation: {rl_recs[0]['software']} → {rl_recs[0]['recommended_action']}")
        logging.info("=" * 50)


# ============================================================================
# MAIN
# ============================================================================

def main():
    scanner = EnhancedSecurityScanner()
    csv_file, json_file = scanner.run_scan()

    # Colab auto-download
    try:
        from google.colab import files
        files.download(csv_file)
        files.download(json_file)
    except ImportError:
        logging.info("📥 Files ready locally: CSV + JSON")

    return csv_file, json_file


if _name_ == "_main_":
    logging.info("🚀 Launching Enhanced Backend (Hackathon Mode)")
    main()
