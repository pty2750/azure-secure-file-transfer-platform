# Security Design — Azure Secure File Transfer Platform

## 1. Security Overview

The Azure Secure File Transfer Platform uses multiple security controls to protect file ingestion workflows, detect potentially malicious activity, and support security investigations.

The platform combines file validation, antivirus scanning, threat detection modules, and audit logging.

The application has been tested locally using Azure Functions, Docker, ClamAV, and Azurite.

## 2. Malware Protection

**Technology:** ClamAV Antivirus

Uploaded files are scanned for malware before being accepted into storage.

Security behavior:

- Clean files can proceed through the upload workflow.
- Malware-infected files are rejected.
- Infected files are prevented from entering the accepted-files storage container.
- Malware scanning failures should be treated as security-relevant events requiring investigation.

### Verified Malware Test

The EICAR antivirus test signature was used to verify malware detection without introducing real malware.

**Observed results:**

- ClamAV identified the EICAR signature.
- The upload API rejected the file with HTTP 400.
- The API reported an `INFECTED` scan status.
- The rejected file was not found in accepted-files storage.

## 3. File Validation

The platform provides validation functionality for incoming files.

Validation is intended to prevent unsuitable files from being accepted into the ingestion workflow.

The application also handles duplicate upload attempts.

**Verified behavior:** A duplicate upload returned HTTP 409 Conflict.

## 4. Threat Detection Modules

The platform includes four Python threat detection modules.

### Authentication Threat Detection

Module: `src/auth_threat_detector.py`

Supports analysis of authentication-related activity for potentially suspicious behavior.

### Abnormal Upload Detection

Module: `src/abnormal_upload_detector.py`

Supports identification of unusual file upload activity.

### Malware Threat Detection

Module: `src/malware_threat_detector.py`

Supports analysis of malware-related security events.

### Upload Threat Detection

Module: `src/upload_threat_detector.py`

Supports monitoring of potentially suspicious upload behavior.

These modules provide detection capabilities. Their presence alone does not establish production alerting or continuous monitoring.

## 5. Audit Logging

Module: `src/audit_logger.py`

Audit logging supports security investigations by recording relevant application and security events.

Correlation identifiers can help associate related operations across logs.

Centralized log ingestion, alert routing, and retention policies require separate configuration and verification.

## 6. Container Security

The application uses Docker to package its runtime dependencies.

The containerized environment includes:

- Python-based Azure Functions runtime
- ClamAV antivirus
- Application security modules
- Required Python dependencies

Docker provides a reproducible execution environment but does not independently guarantee container security.

## 7. Security Testing

The following behavior has been verified locally:

| Security Test | Observed Result |

|---|---|

| Health endpoint | Successful response |

| Clean file upload | Accepted |

| File validation | Successful |

| Duplicate upload | HTTP 409 |

| EICAR malware detection | Detected |

| Malware upload | HTTP 400 |

| Malware in accepted storage | Not present |

| Selected automated tests | 58 passed, plus 10 subtests |

## 8. Known Limitations

- The complete API and audit logging integration test suite has not yet passed in the isolated test-container environment.
- Production Azure deployment and cloud security configuration have not been verified.
- Managed identities, centralized security alerting, and CI/CD enforcement should not be considered implemented without additional verification.
- Further testing is required before treating the platform as production-ready.

## 9. Future Security Enhancements

Potential enhancements include:

- Azure managed identity integration
- Azure Key Vault for secrets management
- Microsoft Defender for Cloud integration
- Centralized monitoring through Azure Monitor
- Automated security alerts
- CI/CD security scanning
- Additional end-to-end integration tests
- Container image vulnerability scanning

## 10. Security Design Principle

The platform follows a defense-in-depth approach by combining validation, malware scanning, suspicious activity detection, and audit logging.

The objective is to reject unsafe files before storage and maintain useful security evidence for troubleshooting and investigation.
