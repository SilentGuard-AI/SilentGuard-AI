# SilentGuard AI – Source Code Repository

SilentGuard AI is an AWS-based system that detects suspicious scam calls in real time and notifies guardians when a potential risk is identified.

**Website link:** https://d3fxslbm1g4ngs.cloudfront.net/

This repository contains the **application source code** only:
- Frontend (React, served via CloudFront)
- AWS Lambda functions

The full deployment package — infrastructure templates and installation instructions — is available in the Google Drive folder linked below.

## Tech Stack
Amazon Connect + Contact Lens, EventBridge, Lambda (Node.js), DynamoDB, SNS/SES, API Gateway, Cognito, React + CloudFront.

## Repository Contents
```bash
/
├── WebFrontend/
│   ├── static/
│   │   └── js/
│   ├── asset-manifest.json
│   └── index.html
│
└── lambdas/
    ├── aisilentguard-api/
    ├── aisilentguard-getMe/
    └── aisilentguard-analyzeScam
```

This repository does **not** include the AWS infrastructure package.

## Full Installation & Deployment Package
The complete installation package is available here:

📂 [Google Drive Installation Folder](https://drive.google.com/drive/folders/1Vglkw6AxOfiEPWT9KIa7b8RF9-lAdHVy)

The folder contains:
- CloudFormation template
- API Gateway Swagger/OpenAPI export
- Amazon Connect contact flow exports
- Deployment scripts
- Cleanup scripts
- Environment example file (`.env.example`)
- Full installation guide
- Architecture documentation
- Feature / use-case documentation

> Follow the installation steps from the instructions inside the Google Drive folder.
