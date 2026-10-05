import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Any, Optional, Tuple
from pydantic import BaseModel
from apk_analyzer.schema import CriticalFinding

class AppContainerComponent(BaseModel):
    name: str
    component_type: str  # activity | service | receiver | provider
    is_exported: bool
    permission: Optional[str] = None
    intent_filters: List[str] = []

class ComponentInspectionResult(BaseModel):
    total_activities: int = 0
    total_services: int = 0
    total_receivers: int = 0
    total_providers: int = 0
    exported_count: int = 0
    unprotected_exported_count: int = 0
    components: List[AppContainerComponent] = []

class ComponentInspector:
    """
    Inspects Android app components (Activities, Services, Receivers, Providers)
    from AndroidManifest.xml to detect exported components, misconfigured intent-filters,
    and stealth/headless entry points.
    """
    def __init__(self, root: Optional[ET.Element], target_sdk: int = 28):
        self.root = root
        self.target_sdk = target_sdk

    def inspect(self) -> Tuple[ComponentInspectionResult, List[CriticalFinding]]:
        result = ComponentInspectionResult()
        findings: List[CriticalFinding] = []

        if self.root is None:
            return result, findings

        application = self.root.find("application")
        if application is None:
            return result, findings

        # Enumerate each component type
        components_to_scan = [
            ("activity", "activity"),
            ("activity-alias", "activity"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider")
        ]

        for tag_name, comp_type in components_to_scan:
            for elem in application.findall(tag_name):
                comp = self._parse_component(elem, comp_type)
                result.components.append(comp)

                if comp_type == "activity":
                    result.total_activities += 1
                elif comp_type == "service":
                    result.total_services += 1
                elif comp_type == "receiver":
                    result.total_receivers += 1
                elif comp_type == "provider":
                    result.total_providers += 1

                if comp.is_exported:
                    result.exported_count += 1
                    if not comp.permission:
                        result.unprotected_exported_count += 1

        # Evaluate Component Misconfigurations & Threats
        findings.extend(self._evaluate_component_threats(result))

        return result, findings

    def _parse_component(self, elem: ET.Element, comp_type: str) -> AppContainerComponent:
        name = self._get_attr(elem, ["name", "android:name"]) or "UnknownComponent"
        permission = self._get_attr(elem, ["permission", "android:permission", "readPermission", "android:readPermission"])
        
        # Extract intent-filter action names
        intent_actions = []
        for if_elem in elem.findall("intent-filter"):
            for action_elem in if_elem.findall("action"):
                action_name = self._get_attr(action_elem, ["name", "android:name"])
                if action_name:
                    intent_actions.append(action_name)

        # Resolve exported state
        exported_attr = self._get_attr(elem, ["exported", "android:exported"])
        if exported_attr is not None:
            is_exported = exported_attr.lower() == "true"
        else:
            # Android default export resolution rules
            if len(intent_actions) > 0:
                is_exported = True
            elif comp_type == "provider" and self.target_sdk < 17:
                is_exported = True
            else:
                is_exported = False

        return AppContainerComponent(
            name=name,
            component_type=comp_type,
            is_exported=is_exported,
            permission=permission,
            intent_filters=intent_actions
        )

    def _evaluate_component_threats(self, result: ComponentInspectionResult) -> List[CriticalFinding]:
        findings: List[CriticalFinding] = []

        # Finding 1: High ratio of unprotected exported components
        if result.unprotected_exported_count > 0:
            findings.append(CriticalFinding(
                category="Components",
                indicator=f"Exposed Unprotected Components ({result.unprotected_exported_count})",
                description=f"App exposes {result.unprotected_exported_count} exported component(s) without enforcing security permissions, allowing third-party apps to invoke them.",
                severity="High" if result.unprotected_exported_count > 2 else "Medium"
            ))

        # Finding 2: Unprotected Boot Receiver
        for comp in result.components:
            if comp.component_type == "receiver" and comp.is_exported and not comp.permission:
                for action in comp.intent_filters:
                    if "BOOT_COMPLETED" in action or "QUICKBOOT" in action:
                        findings.append(CriticalFinding(
                            category="Components",
                            indicator="Exposed Boot Broadcast Receiver",
                            description=f"Receiver '{comp.name}' listens for boot completion events without permission protection, enabling persistence and intent spoofing attacks.",
                            severity="High"
                        ))

        # Finding 3: Stealth / Headless Background Service dominance
        if result.total_services > 0 and result.total_activities == 0:
            findings.append(CriticalFinding(
                category="Components",
                indicator="Headless Application Architecture",
                description="Application contains background Services but zero UI Activities, indicative of a covert payload or daemon service.",
                severity="Critical"
            ))

        # Finding 4: Unprotected Exported Content Provider
        for comp in result.components:
            if comp.component_type == "provider" and comp.is_exported and not comp.permission:
                findings.append(CriticalFinding(
                    category="Components",
                    indicator="Unprotected Exported Content Provider",
                    description=f"Content Provider '{comp.name}' is exported without read/write permissions, exposing app databases to unauthorized data extraction or SQL injection.",
                    severity="Critical"
                ))

        return findings

    def _get_attr(self, element: ET.Element, candidate_names: List[str]) -> Optional[str]:
        for attr_key, attr_val in element.attrib.items():
            clean_key = attr_key.split("}")[-1] if "}" in attr_key else attr_key
            if clean_key in candidate_names or attr_key in candidate_names:
                return attr_val
        return None
