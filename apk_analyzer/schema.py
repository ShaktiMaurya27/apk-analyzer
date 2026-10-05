from typing import List, Optional
from pydantic import BaseModel, Field

class AppMetadata(BaseModel):
    package_name: str = "Unknown"
    app_name: str = "Unknown"
    version_name: str = "Unknown"
    version_code: str = "Unknown"
    target_sdk: int = 0
    min_sdk: int = 0
    file_size_bytes: int = 0
    sha256: str = ""

class Verdict(BaseModel):
    risk_score: int = Field(default=0, ge=0, le=100)
    classification: str = "Safe"  # Safe | Suspicious | Malicious
    confidence_level: str = "Low"  # Low | Medium | High
    summary: str = ""

class CriticalFinding(BaseModel):
    category: str  # Permissions | Bytecode | Network | Certificate | Components
    indicator: str
    description: str
    severity: str  # Critical | High | Medium | Low

class DangerousPermission(BaseModel):
    name: str
    reason: str

class ObfuscationAndPacking(BaseModel):
    is_packed: bool = False
    packer_detected: Optional[str] = None
    entropy_level: str = "Normal"  # Normal | High | Extremely High

class RiskBreakdown(BaseModel):
    critical_findings: List[CriticalFinding] = Field(default_factory=list)
    dangerous_permissions: List[DangerousPermission] = Field(default_factory=list)
    suspicious_apis_and_calls: List[str] = Field(default_factory=list)
    extracted_endpoints: List[str] = Field(default_factory=list)
    obfuscation_and_packing: ObfuscationAndPacking = Field(default_factory=ObfuscationAndPacking)

class SecurityReport(BaseModel):
    app_metadata: AppMetadata
    verdict: Verdict
    risk_breakdown: RiskBreakdown
    recommendations: List[str] = Field(default_factory=list)
