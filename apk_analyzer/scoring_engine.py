from typing import List, Tuple
from apk_analyzer.schema import (
    Verdict,
    CriticalFinding,
    DangerousPermission,
    ObfuscationAndPacking
)

class ScoringEngine:
    """
    Aggregates findings from manifest, component, bytecode, network, and certificate
    auditors to compute a 0-100 Risk Score, Verdict classification, confidence level,
    summary, and actionable recommendations.
    """
    def compute_verdict(
        self,
        critical_findings: List[CriticalFinding],
        dangerous_permissions: List[DangerousPermission],
        obfuscation_info: ObfuscationAndPacking,
        extracted_endpoints: List[str]
    ) -> Tuple[Verdict, List[str]]:
        
        raw_score = 0
        has_critical = False
        has_high = False
        
        # 1. Score Critical Findings
        for finding in critical_findings:
            if finding.severity == "Critical":
                has_critical = True
                if "Command-and-Control" in finding.indicator or "Exfiltration" in finding.indicator:
                    raw_score += 35
                elif "Accessibility" in finding.indicator or "Banking Trojan" in finding.indicator:
                    raw_score += 30
                elif "SMS Interception" in finding.indicator or "Spyware" in finding.indicator:
                    raw_score += 30
                elif "DexClassLoader" in finding.indicator or "Disguised" in finding.indicator:
                    raw_score += 25
                elif "Packer" in finding.indicator:
                    raw_score += 20
                else:
                    raw_score += 25
            elif finding.severity == "High":
                has_high = True
                if "Debug Certificate" in finding.indicator:
                    raw_score += 20
                elif "Exposed Boot" in finding.indicator or "Shell Execution" in finding.indicator:
                    raw_score += 20
                else:
                    raw_score += 20
            elif finding.severity == "Medium":
                raw_score += 8
            elif finding.severity == "Low":
                raw_score += 3

        # 2. Score Dangerous Permissions (Capped at 25 points)
        perm_score = min(25, len(dangerous_permissions) * 5)
        raw_score += perm_score

        # 3. Score Obfuscation & Packing
        if obfuscation_info.is_packed:
            raw_score += 15
        elif obfuscation_info.entropy_level == "High":
            raw_score += 8

        # Cap score between 0 and 100
        risk_score = min(100, max(0, raw_score))

        # 4. Map Classification
        if risk_score >= 70:
            classification = "Malicious"
        elif risk_score >= 40:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # 5. Determine Confidence Level
        if has_critical:
            confidence = "High"
        elif has_high or obfuscation_info.is_packed or len(dangerous_permissions) >= 3:
            confidence = "Medium"
        else:
            confidence = "Low"

        # 6. Generate Summary
        summary = self._generate_summary(risk_score, classification, critical_findings, dangerous_permissions)

        # 7. Generate Actionable Recommendations
        recommendations = self._generate_recommendations(classification, critical_findings, dangerous_permissions)

        verdict = Verdict(
            risk_score=risk_score,
            classification=classification,
            confidence_level=confidence,
            summary=summary
        )

        return verdict, recommendations

    def _generate_summary(
        self,
        risk_score: int,
        classification: str,
        findings: List[CriticalFinding],
        dangerous_perms: List[DangerousPermission]
    ) -> str:
        if classification == "Malicious":
            top_indicators = [f.indicator for f in findings if f.severity in ("Critical", "High")]
            indicators_str = ", ".join(top_indicators[:3]) if top_indicators else "High threat profile"
            return (
                f"Application classified as MALICIOUS with a Risk Score of {risk_score}/100. "
                f"Static analysis detected severe security threats including: {indicators_str}."
            )
        elif classification == "Suspicious":
            return (
                f"Application classified as SUSPICIOUS with a Risk Score of {risk_score}/100. "
                f"Package contains {len(dangerous_perms)} dangerous permission(s) and elevated threat indicators requiring manual review."
            )
        else:
            return (
                f"Application classified as SAFE with a Risk Score of {risk_score}/100. "
                f"Standard application behavior observed with no critical malicious evasion or exfiltration traits detected."
            )

    def _generate_recommendations(
        self,
        classification: str,
        findings: List[CriticalFinding],
        dangerous_perms: List[DangerousPermission]
    ) -> List[str]:
        recs = []

        if classification == "Malicious":
            recs.append("DO NOT INSTALL OR EXECUTE: Package poses an immediate security threat to device data and privacy.")
            recs.append("Block app hash across Enterprise EDR and Mobile Threat Defense (MTD) solutions.")
        elif classification == "Suspicious":
            recs.append("Exercise caution before installing. Conduct dynamic behavioral sandbox analysis prior to deployment.")

        for f in findings:
            if "Debug Certificate" in f.indicator:
                recs.append("Re-sign the APK with an official production certificate before distributing.")
            elif "Exposed" in f.indicator:
                recs.append("Enforce explicit permissions or set android:exported='false' on unneeded exposed components.")
            elif "Insecure Plain HTTP" in f.indicator:
                recs.append("Migrate all plain HTTP network calls to encrypted HTTPS endpoints with Network Security Config.")
            elif "DexClassLoader" in f.indicator:
                recs.append("Audit dynamic class loading calls to ensure external secondary DEX files are cryptographically verified.")

        if not recs:
            recs.append("Application passes standard static security checks. Maintain routine monitoring.")

        return recs
