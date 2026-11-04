# Azure Secure File Transfer Platform — System Architecture

## 1. Overview

The Azure Secure File Transfer Platform is a Python-based file ingestion and security monitoring application built using Azure Functions.

The platform has been tested locally using Docker, ClamAV antivirus, and Azurite (Azure Storage emulator).

Its purpose is to validate uploaded files, detect malware, monitor suspicious activity, and securely store accepted files.

## 2. Architecture Diagram

```mermaid

flowchart TD

&#x20;   A[Client / File Uploader] --> B[Azure Functions HTTP API]

&#x20;   B --> C[File Validation]

&#x20;   C --> D[ClamAV Malware Scanner]

&#x20;   D --> E{Security Decision}

&#x20;   E -->|Clean| F[Azure Blob Storage / Azurite]

&#x20;   E -->|Infected| G[Reject File]

&#x20;   B --> H[Threat Detection Modules]

&#x20;   H --> I[Audit Logging]

```

## 3. Core Components

### Azure Functions

Provides HTTP endpoints for health checks, file uploads, and validation.

### File Validation

Applies validation rules to incoming files before they are accepted.

### ClamAV Antivirus

Scans files for malware and rejects infected uploads.

### Azure Blob Storage / Azurite

Stores accepted files. Azurite is used to emulate Azure Blob Storage during local development.

### Threat Detection

The project includes modules for:

- Authentication threat detection
- Abnormal upload detection
- Malware threat detection
- Upload activity monitoring

### Audit Logging

Records security-relevant events to support monitoring and investigations.

### Docker

Packages the Azure Functions application and ClamAV dependencies into a containerized environment.

## 4. API Endpoints

| Method | Endpoint | Purpose |

|---|---|---|

| GET | `/api/health` | Application health check |

| POST | `/api/upload` | Upload and scan files |

| POST | `/api/validate` | Validate uploaded files |

## 5. Verified Local Security Tests

- Health endpoint returned a successful response.
- Clean file uploads and validation succeeded.
- Duplicate uploads returned HTTP 409.
- EICAR antivirus test files were detected by ClamAV.
- Malware uploads were rejected with HTTP 400.
- Rejected malware was not stored in the accepted-files container.
- Selected automated tests passed: 58 tests and 10 subtests.

## 6. Current Limitations

The complete API and audit logging integration test suite has not yet passed in the isolated test-container environment.

Local verification does not establish that the application has been deployed to production Azure infrastructure.

## 7. Future Enhancements

Potential improvements include Azure deployment, managed identity integration, centralized monitoring, CI/CD automation, and additional integration testing.
