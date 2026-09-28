# SNH - SecureMusiciansHub

[![Language](https://img.shields.io/badge/Language-PHP%208.x-777BB4.svg)](https://www.php.net/)
[![Database](https://img.shields.io/badge/Database-MySQL-4479A1.svg)](https://www.mysql.com/)
[![Web Server](https://img.shields.io/badge/Web%20Server-Apache2-D22128.svg)](https://httpd.apache.org/)
[![Security](https://img.shields.io/badge/Security-OWASP%20Hardened-blue.svg)](https://owasp.org/)

[Project Specifications](2025%20web-project-specs.pdf) | [Database Schema](database.sql) | [Source Code](var/www/)

This repository contains the design and implementation of **SecureMusiciansHub**, a secure web platform for musicians to share lyrics and audio tracks. Built using native PHP and MySQL without external frameworks or template engines, the application enforces defense-in-depth principles against modern web attack vectors.

The project was developed for the **System and Network Hacking** (SNH) course (Master of Science in Computer Engineering, **Università di Pisa**), Academic Year 2025–2026.

---

## Project Overview

**SecureMusiciansHub** provides a hardened media-sharing platform tailored for musical creators. Registered artists can publish lyrics as readable text and attach original audio compositions (MP3 format), optionally designating submissions as premium assets. Access to premium tracks and lyrics is strictly confined to verified premium accounts, with account upgrades managed through an administrative panel.

Because the project focuses on adversarial resilience, every component is architected under strict threat modeling to prevent exploitation, state tampering, unauthorized privilege escalation, and data exfiltration.

Key capabilities of the system include:
- **Zero-Framework Architecture**: Implemented strictly in native PHP 8.x and vanilla JavaScript/HTML/CSS without third-party frameworks or template engines, adhering to strict coursework specifications.
- **Role-Based Access Control (RBAC)**: Multi-tier privilege model distinguishing `REGULAR`, `PREMIUM`, and `ADMIN` users, with real-time database validation on every sensitive operation.
- **Hardened Media Pipeline**: Secure upload and streaming download architecture storing audio files directly as binary blobs (`LONGBLOB`) in MySQL, neutralizing Local File Inclusion (LFI) and remote script execution.
- **Multi-Phase Account Lifecycle**: Self-registration with email activation, account lockout upon brute-force detection, email-based unlocking tokens, and cryptographically secure password recovery.
- **Redundant Defense Matrix**: Coordinated protections against SQL Injection (SQLi), Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Session Fixation/Hijacking, and Clickjacking.
- **Automated Token Management**: Database-driven lifecycle management for one-time tokens using MySQL Event Scheduler routines.
- **Audit Logging & Forensics**: Centralized security logger recording request contexts (client IP, URI, HTTP method, User-Agent) outside the web root for post-incident analysis.

---

## Technical Specifications

| System Component | Technology / Mechanism | Specification / Details |
| :--- | :---: | :--- |
| **Backend Environment** | Native PHP 8.x | Procedural and OOP architecture without external frameworks |
| **Web Server** | Apache HTTP Server (2.4+) | Virtual host configuration with public/private directory isolation |
| **Authentication & Hashing** | Bcrypt (`PASSWORD_DEFAULT`) | One-way salted hashing with strict password complexity requirements |
| **Session Hardening** | PHP Session Management | `SameSite=Strict`, `HttpOnly`, `use_only_cookies`, 10-minute TTL guard |
| **CSRF Defense** | Synchronizer Token Pattern | Cryptographically secure 32-byte tokens validated via `hash_equals()` |
| **Content Security Policy** | HTTP CSP Header | `script-src 'self'; frame-ancestors 'none';` blocking inline scripts & iframes |
| **File Upload Validation** | PHP `finfo` MIME Inspection | Magic-byte MIME checking (`audio/mpeg`, `audio/mp3`, `audio/x-mpeg-3`), 10 MB limit |
| **Automated Housekeeping** | MySQL Event Scheduler | Periodic daemon routines purging expired activation, unlock, and recovery tokens |
| **Audit Logging** | File-based Rotating Logger | JSON-contextualized logs stored outside the public document root with `LOCK_EX` |

---

## Security Architecture & Threat Mitigation

### 1. Defensive Countermeasures Matrix

| Threat / Attack Vector | Defensive Mechanism | Implementation Specifics |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Prepared Statements & Parameter Binding | All database queries use PDO prepared statements with strict parameter binding (`bindValue` and typed parameters). No string interpolation or concatenation is used. |
| **Race Conditions / Concurrency** | Pessimistic Locking & Transactions | Failed login tracking utilizes `SELECT ... FOR UPDATE` within explicit database transactions (`beginTransaction` / `commit` / `rollBack`) to prevent concurrent brute-force bypass. |
| **Cross-Site Scripting (XSS)** | Context-Aware Encoding & Strict CSP | All user-supplied inputs rendered in HTML are escaped using `htmlspecialchars()`. Additionally, HTTP response headers enforce `script-src 'self'` to prevent arbitrary script execution. |
| **Cross-Site Request Forgery (CSRF)** | Single-Use Anti-CSRF Tokens | Forms embed single-use tokens generated via `random_bytes(32)`. Submissions are verified using timing-attack-safe `hash_equals()` and invalidated upon validation. |
| **Clickjacking** | Frame Restriction | The HTTP CSP header enforces `frame-ancestors 'none'`, prohibiting pages from being embedded in iframes or external framesets. |
| **Session Fixation & Hijacking** | Regenerate ID & Strict Cookie Flags | Session IDs are regenerated via `session_regenerate_id(true)` upon successful authentication. Cookies enforce `HttpOnly` and `SameSite=Strict`. |
| **Session Expiration** | Activity Guard | The session manager tracks the `lastAccess` timestamp, terminating the session and clearing client cookies after 10 minutes of inactivity. |
| **Brute-Force & Enumeration** | Account Lockout & Generic Errors | Accounts lock after 10 consecutive failed login attempts. Authentication and password reset endpoints return uniform error messages to prevent username harvesting. |
| **Unrestricted File Upload / RCE** | MIME Inspection & Blob Storage | Audio uploads are validated via PHP Fileinfo magic-byte inspection (not client file extensions) and stored directly as database blobs, eliminating web-accessible script execution paths. |
| **Insecure Direct Object Reference** | Real-Time Role Enforcement | Role authorizations (`REGULAR`, `PREMIUM`, `ADMIN`) are queried live from the database on sensitive requests (`Database::fetchUpdatedRole`) to prevent stale session elevation. |

### 2. Architecture & Directory Segregation

The system separates routable web assets from internal business logic, database credentials, and security logs:

- **Public Root (`var/www/html/`)**: Contains only publicly accessible PHP endpoints and styling. All user requests enter here.
- **Private Domain (`var/www/private/`)**: Located outside the Apache `DocumentRoot`. Contains database configurations, connection handlers, session guards, CSRF utilities, and logging mechanisms. Files in this folder cannot be queried directly via HTTP.
- **Audit Storage (`var/www/logs/`)**: Write-only directory for the web server process containing timestamped daily logs (`security-report-YYYYMMDD.log`).

### 3. Account Lifecycle & Token Management

- **Account Activation**: Newly registered users are stored in `pending_users` with a 32-byte cryptographically secure token. Activation links expire after 24 hours.
- **Account Lockout & Unlocking**: When consecutive failed login attempts reach 10, the account is locked and an unlock token (72-hour validity) is dispatched to the user's registered email.
- **Password Recovery**: Recovery requests generate a token whose SHA-256 hash is saved in `password_recovery`. Links expire after 5 minutes and immediately invalidate upon completion.
- **Scheduled Token Cleanups**: MySQL scheduled events continuously purge expired records from `pending_users`, `account_unlocking`, and `password_recovery` tables without requiring cron scripts.

---

## Project Structure

```text
SNH-SecureMusiciansHub/
├── 2025 web-project-specs.pdf     # Official project specifications and security guidelines
├── database.sql                    # MySQL schema, table definitions, constraints, and scheduled events
└── var/
    └── www/
        ├── html/                   # Public Web Root (Served by Apache)
        │   ├── activate_account.php # Validates activation tokens and promotes pending users
        │   ├── dashboard.php        # Administrator dashboard for managing user privileges (RBAC)
        │   ├── index.php            # Main portal: post feed, lyrics/audio upload, and audio downloads
        │   ├── login.php            # User authentication, brute-force throttling, and lockout logic
        │   ├── logout.php           # Secure session termination and client-cookie invalidation
        │   ├── password_recovery.php# Initiates password reset requests and sends recovery emails
        │   ├── register.php         # User self-registration and activation email dispatch
        │   ├── reset_confirm.php    # Validates recovery tokens and updates account passwords
        │   ├── style.css            # Custom presentation styling (vanilla CSS)
        │   └── unlock_account.php   # Processes email unlock tokens for locked accounts
        ├── logs/                   # Audit directory for daily security report logs (locked)
        └── private/                # Private Backend Modules (Inaccessible via HTTP)
            ├── config.php           # Centralized configuration constants and operational limits
            ├── csrf.php             # CSRF token generation and validation utilities
            ├── database.php         # PDO database initialization and role resolution logic
            ├── logger.php           # Audit logger capturing IP, URI, HTTP method, and agent data
            └── session.php          # Session security controls, cookie flags, and timeout guards
```

---

## Getting Started

### Prerequisites

- **PHP 8.0+** with the following extensions:
  - `pdo_mysql` (Database interaction)
  - `fileinfo` (MIME validation for audio uploads)
  - `session` (Session management)
- **MySQL 8.0+** or **MariaDB 10.5+**
- **Apache HTTP Server 2.4+** with `mod_rewrite` enabled
- **Mail Transfer Agent (MTA)**: Postfix, Sendmail, or a local SMTP relay configured for PHP `mail()`

### Setup and Configuration

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Dariobande/SNH-SecureMusiciansHub.git
   cd SNH-SecureMusiciansHub
   ```

2. **Initialize the Database**:
   Log in to MySQL as an administrative user and source `database.sql`:
   ```bash
   mysql -u root -p < database.sql
   ```
   This script performs the following tasks:
   - Enables the MySQL `event_scheduler`.
   - Creates the `snh_db` database with `utf8mb4` encoding.
   - Configures the dedicated `snh_user` database account.
   - Creates `users`, `pending_users`, `posts`, `password_recovery`, and `account_unlocking` tables.
   - Registers scheduled events for automated token cleanup.

3. **Deploy Web Application Files**:
   Copy the contents of `var/www` to your server's web directory:
   ```bash
   sudo cp -r var/www/* /var/www/
   ```

4. **Configure Directory Permissions**:
   Ensure proper ownership and permissions so that Apache can serve public files and write to the log directory, while protecting private modules:
   ```bash
   sudo chown -R www-data:www-data /var/www/
   sudo chmod -R 750 /var/www/
   sudo chmod 770 /var/www/logs
   ```

5. **Configure Apache Virtual Host**:
   Configure Apache so that the `DocumentRoot` points specifically to `/var/www/html`:
   ```apache
   <VirtualHost *:80>
       ServerName snh.local
       DocumentRoot /var/www/html

       <Directory /var/www/html>
           Options -Indexes +FollowSymLinks
           AllowOverride None
           Require all granted
       </Directory>

       # Explicitly deny access to private modules and logs if located in parent paths
       <Directory /var/www/private>
           Require all denied
       </Directory>
       <Directory /var/www/logs>
           Require all denied
       </Directory>

       ErrorLog ${APACHE_LOG_DIR}/snh_error.log
       CustomLog ${APACHE_LOG_DIR}/snh_access.log combined
   </VirtualHost>
   ```
   Enable the site and reload Apache:
   ```bash
   sudo a2ensite snh.conf
   sudo systemctl reload apache2
   ```

6. **Update Application Configuration**:
   If database credentials, domain addresses, or SMTP details differ from the defaults, adjust the constants in `/var/www/private/config.php`:
   ```php
   const dbHost = "127.0.0.1";
   const dbName = "snh_db";
   const dbUsername = "snh_user";
   const dbPassword = "super-strong-password";
   const serverEmailAddress = "noreply@snh.com";
   const serverIpAddress = "127.0.0.1";
   ```

7. **Access the Portal**:
   Open your browser and navigate to:
   ```text
   http://127.0.0.1/login.php
   ```
