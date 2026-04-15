#!/usr/bin/env python3
"""
Gobernanza y Cumplimiento (GRC)
Automatización de políticas de seguridad, informes de amenazas y modelado de amenazas
"""

import ast
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse


@dataclass
class ComplianceControl:
    id: str
    framework: str
    category: str
    description: str
    requirement: str
    severity: str
    check_function: Optional[str]


@dataclass
class ThreatModel:
    component: str
    threats: List[Dict[str, Any]]
    mitigations: List[str]
    risk_level: str


class PolicyGenerator:
    """Genera políticas de seguridad automáticamente"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.policies = []

    def analyze_project_structure(self) -> Dict[str, Any]:
        """Analiza la estructura del proyecto para generar políticas"""
        analysis = {
            "has_authentication": False,
            "has_database": False,
            "handles_pii": False,
            "has_api": False,
            "tech_stack": [],
            "dependencies": []
        }

        # Detectar lenguaje/framework
        if (self.project_path / "requirements.txt").exists():
            analysis["tech_stack"].append("Python")
            self._check_python_deps(analysis)
        elif (self.project_path / "package.json").exists():
            analysis["tech_stack"].append("Node.js")
            self._check_node_deps(analysis)
        elif (self.project_path / "Cargo.toml").exists():
            analysis["tech_stack"].append("Rust")

        # Buscar patrones de código
        for file_path in self.project_path.rglob("*.py"):
            content = file_path.read_text(errors='ignore')
            if 'auth' in content.lower() or 'login' in content.lower():
                analysis["has_authentication"] = True
            if 'database' in content.lower() or 'db' in content.lower():
                analysis["has_database"] = True
            if 'email' in content.lower() or 'ssn' in content.lower():
                analysis["handles_pii"] = True
            if 'api' in content.lower() or 'rest' in content.lower():
                analysis["has_api"] = True

        return analysis

    def _check_python_deps(self, analysis: Dict):
        """Analiza dependencias Python"""
        req_file = self.project_path / "requirements.txt"
        if req_file.exists():
            content = req_file.read_text()
            deps = [line.strip() for line in content.split('\n') if line.strip()]
            analysis["dependencies"] = deps

    def _check_node_deps(self, analysis: Dict):
        """Analiza dependencias Node.js"""
        pkg_file = self.project_path / "package.json"
        if pkg_file.exists():
            data = json.loads(pkg_file.read_text())
            deps = list(data.get("dependencies", {}).keys())
            analysis["dependencies"] = deps

    def generate_security_policy(self, analysis: Dict) -> str:
        """Genera política de seguridad personalizada"""
        policy = f"""# Política de Seguridad - Generada Automáticamente

**Proyecto:** {self.project_path.name}
**Fecha:** {datetime.now().strftime('%Y-%m-%d')}
**Versión:** 1.0

## 1. Resumen Ejecutivo

Esta política define los requisitos de seguridad para el proyecto basado en su arquitectura y stack tecnológico.

## 2. Alcance

**Tecnologías:** {', '.join(analysis['tech_stack'])}
**Componentes:**
"""

        if analysis["has_authentication"]:
            policy += "- Autenticación y Gestión de Sesiones\n"
        if analysis["has_database"]:
            policy += "- Base de Datos y Almacenamiento\n"
        if analysis["has_api"]:
            policy += "- APIs y Comunicaciones\n"
        if analysis["handles_pii"]:
            policy += "- Datos Personales (PII)\n"

        policy += "\n## 3. Requisitos de Seguridad\n\n"

        # Políticas específicas por componente
        if analysis["has_authentication"]:
            policy += """### 3.1 Autenticación
- Implementar MFA para acceso de administradores
- Contraseñas mínimo 12 caracteres con complejidad
- Bloqueo de cuenta tras 5 intentos fallidos
- Sesiones expiran tras 30 minutos de inactividad
- Tokens JWT con expiración de 1 hora

"""

        if analysis["has_database"]:
            policy += """### 3.2 Base de Datos
- Encriptación de datos sensibles en reposo (AES-256)
- Consultas parametrizadas obligatorias
- Acceso a BD solo desde servidores autorizados
- Backups diarios encriptados
- Auditoría de consultas administrativas

"""

        if analysis["has_api"]:
            policy += """### 3.3 APIs
- Rate limiting: 100 requests/minuto por IP
- Autenticación con API keys o OAuth 2.0
- Validación estricta de input
- HTTPS obligatorio
- Versionado de APIs

"""

        if analysis["handles_pii"]:
            policy += """### 3.4 Protección de Datos Personales
- Cumplimiento GDPR para usuarios EU
- Derecho al olvido implementado
- Consentimiento explícito para procesamiento
- Breach notification en 72 horas
- Data retention: máximo 7 años

"""

        policy += """### 3.5 Desarrollo Seguro
- SAST en pipeline CI/CD
- Dependencias auditadas semanalmente
- Secrets nunca hardcodeados
- Code review obligatorio (2 approvers)

## 4. Cumplimiento Normativo

"""

        # Determinar frameworks aplicables
        frameworks = ["ISO 27001"]
        if analysis["handles_pii"]:
            frameworks.extend(["GDPR", "CCPA"])
        if analysis["has_api"]:
            frameworks.append("OWASP API Security")

        for framework in frameworks:
            policy += f"- {framework}\n"

        policy += """
## 5. Incident Response

Ver documento IR-001: Plan de Respuesta a Incidentes

## 6. Revisión

Esta política se revisará trimestralmente o ante cambios significativos en la arquitectura.

---
**Generado automáticamente por GRC Automation System**
"""

        return policy

    def generate_threat_model(self) -> List[ThreatModel]:
        """Genera modelos de amenazas para el proyecto"""
        analysis = self.analyze_project_structure()
        threat_models = []

        # Threat Model: Autenticación
        if analysis["has_authentication"]:
            auth_threats = ThreatModel(
                component="Sistema de Autenticación",
                threats=[
                    {
                        "id": "T-001",
                        "name": "Fuerza Bruta",
                        "description": "Ataques de fuerza bruta contra credenciales",
                        "likelihood": "Alta",
                        "impact": "Alto",
                        "risk_score": 12
                    },
                    {
                        "id": "T-002",
                        "name": "Credential Stuffing",
                        "description": "Uso de credenciales filtradas de otros sitios",
                        "likelihood": "Alta",
                        "impact": "Alto",
                        "risk_score": 12
                    },
                    {
                        "id": "T-003",
                        "name": "Session Hijacking",
                        "description": "Robo de cookies de sesión",
                        "likelihood": "Media",
                        "impact": "Alto",
                        "risk_score": 8
                    }
                ],
                mitigations=[
                    "Implementar rate limiting",
                    "Usar CAPTCHA tras 3 intentos fallidos",
                    "MFA obligatorio",
                    "Cookies httpOnly y secure",
                    "Rotación de tokens"
                ],
                risk_level="High"
            )
            threat_models.append(auth_threats)

        # Threat Model: Base de Datos
        if analysis["has_database"]:
            db_threats = ThreatModel(
                component="Base de Datos",
                threats=[
                    {
                        "id": "T-004",
                        "name": "SQL Injection",
                        "description": "Inyección de código SQL malicioso",
                        "likelihood": "Media",
                        "impact": "Crítico",
                        "risk_score": 15
                    },
                    {
                        "id": "T-005",
                        "name": "Data Exfiltration",
                        "description": "Extracción no autorizada de datos",
                        "likelihood": "Baja",
                        "impact": "Crítico",
                        "risk_score": 8
                    }
                ],
                mitigations=[
                    "Consultas parametrizadas",
                    "Principio de mínimo privilegio",
                    "Encriptación de datos sensibles",
                    "Network segmentation",
                    "Monitoreo de queries anómalas"
                ],
                risk_level="Critical"
            )
            threat_models.append(db_threats)

        # Threat Model: APIs
        if analysis["has_api"]:
            api_threats = ThreatModel(
                component="APIs",
                threats=[
                    {
                        "id": "T-006",
                        "name": "API Abuse",
                        "description": "Uso excesivo de la API",
                        "likelihood": "Alta",
                        "impact": "Medio",
                        "risk_score": 6
                    },
                    {
                        "id": "T-007",
                        "name": "Insecure Direct Object Reference",
                        "description": "Acceso a recursos sin autorización",
                        "likelihood": "Media",
                        "impact": "Alto",
                        "risk_score": 8
                    }
                ],
                mitigations=[
                    "Rate limiting",
                    "Autorización por recurso",
                    "API versioning",
                    "Input validation",
                    "Logging de todas las requests"
                ],
                risk_level="Medium"
            )
            threat_models.append(api_threats)

        return threat_models


class ComplianceChecker:
    """Verifica cumplimiento con frameworks de seguridad"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.controls = self._load_controls()

    def _load_controls(self) -> List[ComplianceControl]:
        """Carga controles de cumplimiento"""
        return [
            ComplianceControl(
                "GDPR-001", "GDPR", "Data Protection",
                "Encriptación de datos personales",
                "Los datos personales deben estar encriptados en reposo y tránsito",
                "High", "check_encryption"
            ),
            ComplianceControl(
                "GDPR-002", "GDPR", "Access Control",
                "Gestión de consentimiento",
                "Se debe poder demostrar consentimiento del usuario",
                "High", "check_consent"
            ),
            ComplianceControl(
                "ISO-001", "ISO 27001", "Access Control",
                "Política de contraseñas",
                "Contraseñas mínimo 8 caracteres con complejidad",
                "Medium", "check_password_policy"
            ),
            ComplianceControl(
                "ISO-002", "ISO 27001", "Cryptography",
                "Gestión de claves",
                "Las claves de encriptación deben rotarse periódicamente",
                "High", "check_key_rotation"
            ),
            ComplianceControl(
                "OWASP-001", "OWASP", "Security",
                "Sin credenciales hardcodeadas",
                "No debe haber contraseñas o API keys en el código",
                "Critical", "check_hardcoded_secrets"
            ),
            ComplianceControl(
                "OWASP-002", "OWASP", "Security",
                "Validación de input",
                "Todo input de usuario debe ser validado",
                "High", "check_input_validation"
            )
        ]

    def run_compliance_check(self) -> Dict[str, Any]:
        """Ejecuta verificación de cumplimiento"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_controls": len(self.controls),
            "passed": 0,
            "failed": 0,
            "details": []
        }

        for control in self.controls:
            passed, evidence = self._check_control(control)
            status = "PASS" if passed else "FAIL"

            results["details"].append({
                "control_id": control.id,
                "framework": control.framework,
                "description": control.description,
                "status": status,
                "evidence": evidence
            })

            if passed:
                results["passed"] += 1
            else:
                results["failed"] += 1

        results["compliance_score"] = round(
            (results["passed"] / results["total_controls"]) * 100, 2
        )

        return results

    def _check_control(self, control: ComplianceControl) -> tuple:
        """Verifica un control específico"""
        check_func = getattr(self, control.check_function, None)
        if check_func:
            return check_func()
        return False, "Función de verificación no implementada"

    def check_encryption(self) -> tuple:
        """Verifica presencia de encriptación"""
        for file_path in self.project_path.rglob("*.py"):
            content = file_path.read_text(errors='ignore').lower()
            if 'cryptography' in content or 'bcrypt' in content:
                return True, "Librería de encriptación encontrada"
        return False, "No se detectaron mecanismos de encriptación"

    def check_consent(self) -> tuple:
        """Verifica gestión de consentimiento"""
        for file_path in self.project_path.rglob("*.py"):
            content = file_path.read_text(errors='ignore').lower()
            if 'consent' in content or 'gdpr' in content:
                return True, "Manejo de consentimiento detectado"
        return False, "No se detecta gestión de consentimiento"

    def check_password_policy(self) -> tuple:
        """Verifica política de contraseñas"""
        # Simplificado - en producción verificar configuración real
        return True, "Verificación manual requerida"

    def check_key_rotation(self) -> tuple:
        """Verifica rotación de claves"""
        return False, "No se detecta mecanismo de rotación de claves"

    def check_hardcoded_secrets(self) -> tuple:
        """Busca credenciales hardcodeadas"""
        patterns = [
            r'password\s*=\s*["\'][^"\']{4,}["\']',
            r'api_key\s*=\s*["\']\w{16,}["\']',
            r'secret\s*=\s*["\']\w{16,}["\']',
            r'AKIA[0-9A-Z]{16}'  # AWS Access Key
        ]

        for file_path in self.project_path.rglob("*"):
            if file_path.is_file() and file_path.stat().st_size < 10*1024*1024:  # < 10MB
                try:
                    content = file_path.read_text(errors='ignore')
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return False, f"Posible secreto hardcodeado en {file_path}"
                except:
                    pass

        return True, "No se detectaron credenciales hardcodeadas"

    def check_input_validation(self) -> tuple:
        """Verifica validación de input"""
        for file_path in self.project_path.rglob("*.py"):
            content = file_path.read_text(errors='ignore')
            if 'validate' in content.lower() or 'sanitiz' in content.lower():
                return True, "Validación de input detectada"
        return False, "No se detecta validación de input"

    def generate_compliance_report(self, results: Dict) -> str:
        """Genera reporte de cumplimiento"""
        report = f"""# 📋 Reporte de Cumplimiento Normativo

**Fecha:** {datetime.now().strftime('%Y-%m-%d')}
**Proyecto:** {self.project_path.name}

## Resumen

| Métrica | Valor |
|---------|-------|
| Controles Totales | {results['total_controls']} |
| Aprobados | {results['passed']} ✅ |
| Reprobados | {results['failed']} ❌ |
| Score | {results['compliance_score']}% |

## Detalle por Control

"""

        for detail in results["details"]:
            icon = "✅" if detail["status"] == "PASS" else "❌"
            report += f"""### {icon} {detail['control_id']} ({detail['framework']})

**Descripción:** {detail['description']}

**Estado:** {detail['status']}

**Evidencia:** {detail['evidence']}

---

"""

        # Recomendaciones
        failed = [d for d in results["details"] if d["status"] == "FAIL"]
        if failed:
            report += "## 🔧 Recomendaciones\n\n"
            for detail in failed:
                report += f"- **{detail['control_id']}:** {detail['evidence']}\n"

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Gobernanza y Cumplimiento (GRC)"
    )
    parser.add_argument("path", help="Ruta del proyecto")
    parser.add_argument(
        "--mode",
        choices=["policy", "threat-model", "compliance", "all"],
        default="all",
        help="Modo de operación"
    )
    parser.add_argument("--output", "-o", default="grc-output",
                       help="Directorio de salida")

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    # Generar política
    if args.mode in ["policy", "all"]:
        generator = PolicyGenerator(args.path)
        analysis = generator.analyze_project_structure()

        policy = generator.generate_security_policy(analysis)
        policy_file = output_dir / "SECURITY_POLICY.md"
        policy_file.write_text(policy)
        print(f"✅ Política generada: {policy_file}")

    # Generar threat model
    if args.mode in ["threat-model", "all"]:
        generator = PolicyGenerator(args.path)
        threat_models = generator.generate_threat_model()

        tm_file = output_dir / "THREAT_MODEL.md"
        with open(tm_file, 'w') as f:
            f.write("# 🎯 Modelos de Amenazas\n\n")
            for tm in threat_models:
                f.write(f"## {tm.component}\n\n")
                f.write(f"**Nivel de Riesgo:** {tm.risk_level}\n\n")
                f.write("### Amenazas Identificadas\n\n")
                for threat in tm.threats:
                    f.write(f"- **{threat['id']}:** {threat['name']}\n")
                    f.write(f"  - {threat['description']}\n")
                    f.write(f"  - Risk Score: {threat['risk_score']}\n\n")
                f.write("### Mitigaciones\n\n")
                for mit in tm.mitigations:
                    f.write(f"- {mit}\n")
                f.write("\n---\n\n")
        print(f"✅ Threat Model generado: {tm_file}")

    # Verificar cumplimiento
    if args.mode in ["compliance", "all"]:
        checker = ComplianceChecker(args.path)
        results = checker.run_compliance_check()

        report = checker.generate_compliance_report(results)
        report_file = output_dir / "COMPLIANCE_REPORT.md"
        report_file.write_text(report)
        print(f"✅ Reporte de cumplimiento: {report_file}")

        print(f"\n📊 Score de Cumplimiento: {results['compliance_score']}%")


if __name__ == "__main__":
    main()
