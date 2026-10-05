import json
from typing import Dict, Any, Union
from apk_analyzer.schema import SecurityReport, RiskBreakdown
from apk_analyzer.ingestion import APKContainer
from apk_analyzer.manifest_auditor import ManifestAuditor
from apk_analyzer.component_inspector import ComponentInspector
from apk_analyzer.bytecode_analyzer import BytecodeAnalyzer
from apk_analyzer.network_cert_analyzer import NetworkCertAnalyzer
from apk_analyzer.scoring_engine import ScoringEngine

class APKAnalysisPipeline:
    """
    Complete 7-Phase Static Security Analysis Pipeline for Android APK files.
    """
    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def run(self) -> SecurityReport:
        """
        Executes end-to-end static analysis and returns a validated SecurityReport object.
        """
        # Phase 1: File Ingestion & Metadata Init
        container = APKContainer(self.apk_path)
        try:
            initial_metadata = container.get_initial_metadata()
            raw_manifest = container.get_raw_manifest()

            # Phase 2: Manifest & Permission Auditing
            manifest_auditor = ManifestAuditor(raw_manifest)
            app_metadata = manifest_auditor.extract_metadata(initial_metadata)
            declared_permissions = manifest_auditor.extract_permissions()
            dangerous_permissions, manifest_findings = manifest_auditor.audit_permissions(declared_permissions)

            # Phase 3: Component & Intent Inspection
            component_inspector = ComponentInspector(manifest_auditor.root, target_sdk=app_metadata.target_sdk)
            component_results, component_findings = component_inspector.inspect()

            # Phase 4: Bytecode, API & Obfuscation Analysis
            bytecode_analyzer = BytecodeAnalyzer(container)
            obfuscation_info, suspicious_apis, bytecode_findings = bytecode_analyzer.analyze()

            # Phase 5: Network Endpoints & Certificate Validation
            network_cert_analyzer = NetworkCertAnalyzer(container)
            extracted_endpoints, net_cert_findings = network_cert_analyzer.analyze()

            # Aggregate all critical findings across phases
            all_critical_findings = (
                manifest_findings +
                component_findings +
                bytecode_findings +
                net_cert_findings
            )

            # Phase 6: Threat Scoring & Classification
            scoring_engine = ScoringEngine()
            verdict, recommendations = scoring_engine.compute_verdict(
                critical_findings=all_critical_findings,
                dangerous_permissions=dangerous_permissions,
                obfuscation_info=obfuscation_info,
                extracted_endpoints=extracted_endpoints
            )

            # Phase 7: Assemble Final Security Report
            risk_breakdown = RiskBreakdown(
                critical_findings=all_critical_findings,
                dangerous_permissions=dangerous_permissions,
                suspicious_apis_and_calls=suspicious_apis,
                extracted_endpoints=extracted_endpoints,
                obfuscation_and_packing=obfuscation_info
            )

            report = SecurityReport(
                app_metadata=app_metadata,
                verdict=verdict,
                risk_breakdown=risk_breakdown,
                recommendations=recommendations
            )

            return report

        finally:
            container.close()

    def run_json(self, indent: int = 2) -> str:
        """Runs the pipeline and returns the analysis report as a formatted JSON string."""
        report = self.run()
        return report.model_dump_json(indent=indent)
