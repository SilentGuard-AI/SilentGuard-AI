# SilentGuard AI - Source Code Repository

SilentGuard AI is an AWS-based system designed to help detect suspicious scam calls and notify guardians when a potential risk is identified.

This repository contains the main source code of the project, including:

Frontend source code
AWS Lambda source code

The full deployment package, including infrastructure files and installation instructions, is available in the Google Drive folder linked below.

## Repository Contents

This repository includes only the application source code:
```bash
/
├── WebFrontend/
│   ├── static/
|        └── js/
│   ├── asset-manifest.json
│   └── index.html
│
└── lambdas/
    ├── aisilentguard-api/
    ├── aisilentguard-getMe/
    ├── createGuardian/
    ├── aisilentguard-api/
    └── getGuardians/
```
The repository does not include the full AWS infrastructure package.

## Full Installation and Deployment Package

The complete installation package is available in the following Google Drive folder:

Google Drive Installation Folder:
[https://drive.google.com/drive/folders/1Vglkw6AxOfiEPWT9KIa7b8RF9-lAdHVy]

### The Google Drive folder contains:

* CloudFormation template
* API Gateway Swagger/OpenAPI export
* Amazon Connect Contact Flow exports
* Deployment scripts
* Cleanup scripts
* Environment example file
* Full installation guide
* Architecture documentation
* Feature/use-case documentation

The technical installation process should be followed from the files and instructions inside the Google Drive folder.
