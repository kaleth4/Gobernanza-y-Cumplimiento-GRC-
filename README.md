# 📋 Gobernanza y Cumplimiento (GRC)

Sistema de automatización de políticas de seguridad, generación de modelos de amenazas (Threat Modeling) y verificación de cumplimiento normativo (GDPR, ISO 27001, OWASP).

## ✨ Características

- **📄 Políticas Automáticas**: Genera políticas de seguridad basadas en la arquitectura del proyecto
- **🎯 Threat Modeling**: Crea modelos de amenazas antes de escribir código
- **✅ Compliance Checking**: Verifica cumplimiento con GDPR, ISO 27001, OWASP
- **📊 Reportes**: Genera reportes ejecutivos de cumplimiento
- **🔍 Análisis de Código**: Detecta dependencias y patrones de seguridad

## 🚀 Instalación

```bash
cd gobernanza-cumplimiento-gcr
pip install -r requirements.txt
```

## 📋 Requisitos

```
python 3.8+
```

## 🎯 Uso

### Generar Todo (Política + Threat Model + Compliance)

```bash
python grc-automation.py /path/to/project --mode all -o output/
```

### Solo Política de Seguridad

```bash
python grc-automation.py /path/to/project --mode policy
```

### Solo Threat Modeling

```bash
python grc-automation.py /path/to/project --mode threat-model
```

### Solo Verificación de Cumplimiento

```bash
python grc-automation.py /path/to/project --mode compliance
```

## 📊 Controles Implementados

| ID | Framework | Categoría | Descripción |
|----|-----------|-----------|-------------|
| GDPR-001 | GDPR | Data Protection | Encriptación de datos personales |
| GDPR-002 | GDPR | Access Control | Gestión de consentimiento |
| ISO-001 | ISO 27001 | Access Control | Política de contraseñas |
| ISO-002 | ISO 27001 | Cryptography | Gestión de claves |
| OWASP-001 | OWASP | Security | Sin credenciales hardcodeadas |
| OWASP-002 | OWASP | Security | Validación de input |

## 🎯 Modelos de Amenazas

El sistema detecta automáticamente:
- **Autenticación**: Fuerza bruta, credential stuffing, session hijacking
- **Base de Datos**: SQL Injection, data exfiltration
- **APIs**: API abuse, IDOR (Insecure Direct Object Reference)

### Ejemplo de Output

```markdown
## Sistema de Autenticación

**Nivel de Riesgo:** High

### Amenazas Identificadas
- **T-001:** Fuerza Bruta
  - Ataques de fuerza bruta contra credenciales
  - Risk Score: 12

- **T-002:** Credential Stuffing
  - Uso de credenciales filtradas de otros sitios
  - Risk Score: 12

### Mitigaciones
- Implementar rate limiting
- Usar CAPTCHA tras 3 intentos fallidos
- MFA obligatorio
```

## 📄 Políticas Generadas

### Ejemplo de Política

```markdown
# Política de Seguridad - Generada Automáticamente

## Alcance
**Tecnologías:** Python
**Componentes:**
- Autenticación y Gestión de Sesiones
- Base de Datos y Almacenamiento
- APIs y Comunicaciones

## Requisitos de Seguridad

### Autenticación
- Implementar MFA para acceso de administradores
- Contraseñas mínimo 12 caracteres
- Bloqueo de cuenta tras 5 intentos fallidos

### Base de Datos
- Encriptación AES-256
- Consultas parametrizadas obligatorias
- Backups diarios encriptados
```

## 📊 Reporte de Cumplimiento

```
📋 Reporte de Cumplimiento Normativo

| Métrica | Valor |
|---------|-------|
| Controles Totales | 6 |
| Aprobados | 4 ✅ |
| Reprobados | 2 ❌ |
| Score | 66.67% |

## Detalle por Control

✅ GDPR-001 (Data Protection)
Estado: PASS
Evidencia: Librería de encriptación encontrada

❌ ISO-002 (Cryptography)
Estado: FAIL
Evidencia: No se detecta mecanismo de rotación de claves
```

## 🔄 Integración CI/CD

```yaml
# .github/workflows/grc.yml
name: GRC Check
on: [push]

jobs:
  grc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - run: pip install -r requirements.txt
      - run: python grc-automation.py . --mode all
      - uses: actions/upload-artifact@v2
        with:
          name: grc-reports
          path: grc-output/
```

## 🏗️ Extensión

### Agregar Nuevo Control

```python
ComplianceControl(
    "MI-001",           # ID único
    "Framework",        # GDPR, ISO, OWASP, etc.
    "Categoría",        # Cryptography, Access Control, etc.
    "Descripción",      # Descripción corta
    "Requerimiento",    # Requerimiento detallado
    "Severidad",        # Low, Medium, High, Critical
    "check_function"    # Nombre de función de verificación
)
```

### Agregar Nuevo Threat

```python
ThreatModel(
    component="Mi Componente",
    threats=[{
        "id": "T-XXX",
        "name": "Mi Amenaza",
        "description": "...",
        "likelihood": "Alta",
        "impact": "Crítico",
        "risk_score": 15
    }],
    mitigations=["Mitigación 1", "Mitigación 2"],
    risk_level="Critical"
)
```

## 🎓 Buenas Prácticas

1. **Ejecutar en PRs**: Verificar cumplimiento antes de mergear
2. **Actualizar threat models**: Revisar trimestralmente
3. **Mantener políticas**: Actualizar cuando cambia la arquitectura
4. **Documentar desviaciones**: Justificar controles no aplicables

## 📄 Licencia

MIT License
