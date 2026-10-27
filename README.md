
# Secure File Integrity Verification and Tamper Detection

**SHA-256 Hashing | RSA Digital Signatures | Flask Web Application**

A Python-based cybersecurity project that uses SHA-256 cryptographic hashing and RSA digital signatures to verify file integrity and detect unauthorized modifications. The project provides a web dashboard for calculating file hashes, signing files, and verifying digital signatures.

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [RSA Key Generation](#rsa-key-generation)
- [Running the Application](#running-the-application)
- [How to Use](#how-to-use)
- [Command-Line Usage](#command-line-usage)
- [Testing](#testing)
- [Expected Results](#expected-results)
- [Security Considerations](#security-considerations)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)

## Overview

File integrity is an important aspect of cybersecurity. Files may be accidentally or maliciously modified during storage or transmission.

This project demonstrates how cryptographic hashing and digital signatures can help detect unauthorized changes to files.

The application uses SHA-256 to generate a unique digest of file contents and RSA digital signatures to verify that a file matches the contents that were originally signed.

A Flask-based web interface makes the cryptographic operations easy to demonstrate and use.

## Problem Statement

File names and file sizes alone cannot establish whether a file's contents remain unchanged. A file may be modified without an obvious visual indication.

This project provides a mechanism to calculate file hashes, digitally sign file contents, verify signatures, and detect changes to signed files.

## Objectives

1. Calculate SHA-256 hashes for files.
2. Generate an RSA public-private key pair.
3. Protect the private key with password-based encryption.
4. Digitally sign file hashes using RSA-PSS and SHA-256.
5. Verify signatures using the corresponding public key.
6. Detect modifications to signed files.
7. Develop a simple web interface using Flask.
8. Test normal, modified, and invalid-file scenarios.

## Features

### 1. SHA-256 Hash Calculation
- Calculates a SHA-256 hash for an uploaded file.
- Displays the hash as a 64-character hexadecimal string.
- Supports text and binary file contents.
- Uses streaming file reading in the cryptographic utility.

### 2. RSA Key Generation
- Generates a 3072-bit RSA key pair.
- Stores the private key in encrypted PEM format.
- Stores the public key separately.
- Uses a password to protect the private key.

### 3. Digital Signature Generation
- Calculates the SHA-256 digest of a file.
- Signs the digest using the RSA private key.
- Uses RSA Probabilistic Signature Scheme (RSA-PSS).
- Creates a detached `.sig` signature file.

### 4. Digital Signature Verification
- Accepts a file and its detached signature.
- Calculates the current SHA-256 digest.
- Verifies the signature using the public key.
- Displays a successful or failed verification result.

### 5. Tamper Detection
- Detects changes to signed file contents.
- Rejects signatures that do not match the file.
- Demonstrates successful verification of unchanged files and failed verification of modified files.

### 6. Web Dashboard
The Flask dashboard provides three operations:

- Calculate SHA-256
- Sign a File
- Verify Integrity

The interface displays operation results, the file name, the SHA-256 hash, and a download option for the generated signature.

### 7. Automated Testing
The project includes 12 automated unit tests covering:

- Verification of unchanged files
- Detection of modified files
- Incorrect public keys
- Signatures belonging to other files
- Empty files
- Binary files
- Missing files
- Malformed signatures
- Missing public keys
- Corrupted signatures
- Swapped signatures
- Verification after restoring original file contents

**Test status:** All 12 tests passed in the local development environment.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| hashlib | SHA-256 hashing |
| cryptography | RSA keys and digital signatures |
| Flask | Web application framework |
| HTML5 | Web interface structure |
| CSS3 | Interface styling |
| unittest | Automated testing |

## How It Works

### Step 1: Calculate the Hash

The application reads the file and calculates its SHA-256 digest.

`H = SHA256(file contents)`

The digest is 256 bits long and is displayed as 64 hexadecimal characters.

### Step 2: Generate the Digital Signature

The application signs the digest using the RSA private key and RSA-PSS.

`S = Sign(private_key, H)`

The resulting signature is stored separately from the original file.

### Step 3: Verify the Signature

The application recalculates the file's digest and verifies the signature using the corresponding public key.

If verification succeeds, the signature matches the supplied file contents under that public key.

### Step 4: Detect Tampering

If a file is modified after signing, its digest changes. The original signature should then fail verification against the modified file.

A valid signature does not independently prove the real-world identity of the public-key owner. That requires a trusted way to establish ownership of the public key.

## Project Structure

```text
secure-file-integrity/
│
├── app.py
├── crypto_utils.py
├── README.md
├── .gitignore
│
├── templates/
│   └── index.html
│
├── keys/
│   ├── private_key.pem
│   └── public_key.pem
│
├── signatures/
│   └── *.sig
│
├── uploads/
│
├── tests/
│   └── test_crypto_utils.py
│
└── .venv/
```

Some directories and files are generated during setup or execution. The `.venv` directory contains the local Python virtual environment.

**Security note:** Never commit your private key, private-key password, or confidential uploaded files to a public GitHub repository.

## Installation

### Prerequisites

- Python 3.10 or later recommended
- pip
- A modern web browser
- Git (optional)

### 1. Clone the Repository

Replace `YOUR_USERNAME` with your GitHub username.

```bash
git clone https://github.com/YOUR_USERNAME/secure-file-integrity.git
cd secure-file-integrity
```

Alternatively, download the repository and open its folder in a terminal.

### 2. Create a Virtual Environment

**Windows:**

```bat
python -m venv .venv
.venv\Scripts\activate
```

**Linux or macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install Flask cryptography
```

If a `requirements.txt` file is included in the repository, install dependencies with:

```bash
python -m pip install -r requirements.txt
```

## RSA Key Generation

Generate the RSA key pair:

```bash
python crypto_utils.py keygen
```

Follow the terminal prompts to create a strong private-key password.

The application generates:

- `keys/private_key.pem` — encrypted RSA private key
- `keys/public_key.pem` — RSA public key

Keep the private key and password secret. Do not overwrite an existing key pair without understanding that previously generated signatures may no longer verify with the new public key.

## Running the Application

Start the Flask application from the project directory:

```bash
python app.py
```

Open the following address in your browser:

http://127.0.0.1:5000

The application runs locally while the Flask server is active.

Press `Ctrl+C` in the terminal to stop the server.

## How to Use

### 1. Calculate SHA-256

1. Open the web dashboard.
2. Find the **Calculate SHA-256** section.
3. Select a file.
4. Click **Calculate Hash**.
5. View the resulting SHA-256 digest.

### 2. Sign a File

1. Find the **Sign a File** section.
2. Select the file.
3. Enter the private-key password.
4. Click **Sign File**.
5. Download the generated `.sig` file.

Keep the signature associated with the correct file.

### 3. Verify an Unchanged File

1. Find the **Verify a File** section.
2. Select the original file.
3. Select its corresponding `.sig` file.
4. Click **Verify Integrity**.
5. Confirm that verification succeeds.

### 4. Demonstrate Tamper Detection

1. Create and sign a test file.
2. Keep the original signature.
3. Modify the file contents and save the file.
4. Upload the modified file with the original signature.
5. Click **Verify Integrity**.
6. Confirm that verification fails.

Do not generate a new signature after modifying the file during this test, because that would sign the modified contents.

## Command-Line Usage

The cryptographic utility can also be used independently of the web interface.

### Generate Keys

```bash
python crypto_utils.py keygen
```

### Calculate a Hash

```bash
python crypto_utils.py hash sample.txt
```

### Sign a File

```bash
python crypto_utils.py sign sample.txt
```

### Verify a Signature

```bash
python crypto_utils.py verify sample.txt signatures/sample.txt.sig
```

On Windows, backslashes can also be used in file paths.

The exact command-line options depend on the implementation in `crypto_utils.py`.

## Testing

Run the automated tests from the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover expected success and failure scenarios using test files and test keys.

| Test Scenario | Expected Result |
|---|---|
| Unchanged file | Verification succeeds |
| Modified file | Verification fails |
| Wrong public key | Verification fails |
| Signature from another file | Verification fails |
| Empty file | Verification succeeds if correctly signed |
| Binary file | Verification succeeds if correctly signed |
| Missing file | Rejected |
| Malformed signature | Rejected |
| Missing public key | Rejected |
| Corrupted signature | Verification fails |
| Swapped signatures | Verification fails |
| Original bytes restored | Original signature verifies again |

**Verified locally:** All 12 automated tests passed.

Run the tests again after modifying the code to confirm the current state.

## Expected Results

| Operation | Expected Output |
|---|---|
| Calculate hash | SHA-256 hexadecimal digest |
| Sign file | Detached `.sig` file |
| Verify unchanged file | Signature verification successful |
| Verify modified file | Signature verification failed |
| Verify with incorrect key | Signature verification failed |
| Verify corrupted signature | Signature verification failed |

## Security Considerations

- **Private-key protection:** Keep the encrypted private key and its password secret.
- **Cryptographic algorithms:** The project uses SHA-256 and RSA-PSS with a 3072-bit RSA key.
- **Signature association:** A detached signature must be matched with the correct file.
- **Public-key trust:** Verification requires an authentic public key. Replacing the trusted public key can undermine identity-related assurances.
- **File uploads:** Uploaded files are stored locally. Remove unnecessary files and avoid uploading confidential data.
- **Upload limit:** The web application limits requests to 50 MB, but a size limit alone does not make uploads fully secure.
- **Password handling:** Never log or display private-key passwords.
- **Development server:** The Flask development server is intended for local demonstration, not direct public deployment.
- **Scope of verification:** A valid signature does not guarantee that a file is malware-free or safe to execute.

This project is an educational implementation and is not a production-ready file security service.

## Limitations

- Designed primarily for local academic demonstrations.
- No user authentication or role-based access control.
- No independent public-key identity certification.
- Uploaded files and signatures are stored locally.
- No complete audit-history dashboard, batch verification, or downloadable reports in the current implementation unless added separately.
- Uses the Flask development server.

## Future Enhancements

Potential future improvements include:

1. File integrity history and audit logs.
2. Original-versus-current hash comparison.
3. Public-key fingerprints and signature metadata.
4. Batch verification of multiple files.
5. Downloadable CSV or PDF reports.
6. Automatic cleanup of temporary files.
7. Stronger upload validation and file lifecycle management.
8. Enhanced dashboard visualizations.
9. Trusted public-key distribution or certificate support.
10. Automated integration tests for web routes.

These are planned enhancements, not features claimed to be implemented in the current version.

## Learning Outcomes

This project demonstrates practical understanding of:

- Cryptographic hash functions
- SHA-256 file fingerprints
- Public-key cryptography
- RSA key generation and private-key encryption
- RSA-PSS digital signatures
- Signature verification and tamper detection
- Flask web application development
- File upload handling
- Python unit testing
- Cybersecurity principles and secure coding considerations

**Project Title:** Secure File Integrity Verification and Tamper Detection Using SHA-256 Hashing and Digital Signatures
