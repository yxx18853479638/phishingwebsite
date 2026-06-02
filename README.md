# User Awareness Platform for Phishing Website Detection

## 1. Project Title

**User Awareness Platform for Phishing Website Detection**

## 2. Project Description

The User Awareness Platform for Phishing Website Detection is a Flask-based web application developed as a Final Year Project. Its purpose is to help users identify suspicious website links, understand common phishing indicators, and improve their awareness of online security risks.

The system analyses submitted URLs using a rule-based phishing detection approach and presents the result in a clear and user-friendly format. Each scan produces a phishing risk classification, a list of suspicious URL features, and practical safety recommendations. In addition to guest access, the platform supports registered user accounts with personal scan history and an administrator dashboard for monitoring scans, statistics, and activity logs.

This project is intended for academic demonstration, learning, and awareness-building rather than as a full production security solution.

## 3. Main Features

- Guest users can check suspicious URLs directly without creating an account
- Registered users can create an account, log in, and save their scan history
- Registered users can view their own previous scan records
- Administrator login with access to a monitoring dashboard
- Admin dashboard shows scan history, phishing statistics, and activity logs
- Rule-based phishing URL detection
- Risk classification into **Safe**, **Suspicious**, and **High Risk**
- Explanation of suspicious URL features detected during analysis
- Safety recommendations for users after each scan
- User awareness page with phishing education content
- SQLite database storage
- Password hashing for user and admin passwords
- Basic input validation for submitted URLs and login/register forms

## 4. Technologies Used

- **Python** - core programming language
- **Flask** - web framework used to build the application
- **SQLite** - lightweight relational database used for local storage
- **HTML** - page structure
- **CSS** - custom styling
- **Bootstrap 5** - responsive frontend layout and UI components
- **Jinja2** - template engine used by Flask for dynamic HTML rendering
- **Werkzeug** - used through Flask for password hashing and security helpers

### Dependency Notes

- The main project dependencies listed in `requirements.txt` are:

```text
Flask>=3.0,<4.0
Flask-WTF>=1.2,<2.0
Werkzeug
gunicorn
```

- `Jinja2` is installed automatically with Flask.
- `sqlite3` does **not** need to be installed separately because it is built into Python.
- `gunicorn` is used as the production web server for Render deployment.

## 5. Folder Structure

```text
cw2/
├── app.py
├── database.py
├── detection.py
├── requirements.txt
├── README.md
├── phishing_platform.db
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── admin_dashboard.html
    ├── admin_login.html
    ├── awareness.html
    ├── base.html
    ├── index.html
    ├── result.html
    ├── user_history.html
    ├── user_login.html
    └── user_register.html
```

### File Overview

- `app.py` - main Flask application containing routes, authentication, session handling, validation, scan processing, and dashboard logic
- `database.py` - database connection and table initialization logic
- `detection.py` - rule-based phishing URL detection logic
- `requirements.txt` - project dependency list
- `phishing_platform.db` - SQLite database file
- `static/css/style.css` - custom frontend styling
- `templates/` - Jinja HTML templates for user and admin pages

## 6. Database Tables

The system uses the following SQLite database tables:

### `admins`
Stores administrator account information.

- `id`
- `username`
- `password_hash`
- `created_at`

### `users`
Stores registered user account information.

- `id`
- `username`
- `password_hash`
- `created_at`

### `scans`
Stores URL scan records and phishing detection results.

- `id`
- `user_id`
- `submitted_url`
- `risk_level`
- `score`
- `explanations`
- `recommendations`
- `scanned_at`

### `activity_logs`
Stores important administrator and system activity records.

- `id`
- `admin_id`
- `action_type`
- `action_details`
- `created_at`

## 7. How to Install

1. Download or clone the project.
2. Open a terminal in the project folder.
3. Create a virtual environment:

```bash
python3 -m venv venv
```

4. Activate the virtual environment:

**macOS / Linux**
```bash
source venv/bin/activate
```

**Windows**
```bash
venv\Scripts\activate
```

5. Install the required dependency:

```bash
pip install -r requirements.txt
```

6. Set a secret key for Flask sessions before running the application:

**macOS / Linux**
```bash
export SECRET_KEY="your-secret-key"
```

**Windows Command Prompt**
```bash
set SECRET_KEY=your-secret-key
```

**Windows PowerShell**
```powershell
$env:SECRET_KEY="your-secret-key"
```

### Installation Notes

- The database tables are created automatically when the Flask application starts.
- SQLite support is already included in Python through `sqlite3`.
- Flask automatically installs its required components, including `Werkzeug` and `Jinja2`.

## 8. How to Run

Start the application with:

```bash
python3 app.py
```

Then open the browser and visit:

```text
http://127.0.0.1:5000
```

### Running Notes

- On first run, the application initializes the SQLite database and creates the required tables automatically.
- The local development server uses the `PORT` environment variable when it is available, otherwise it falls back to port `5000`.
- Debug mode is disabled in `app.py` for deployment readiness.

## 9. Default Admin Account

When the system starts and the `admins` table is empty, it automatically creates a default administrator account for initial testing:

- **Username:** `admin`
- **Password:** `Admin@123`

This default admin account is for **testing and demonstration purposes only**. It should be changed or removed before any real deployment, public demonstration, or production use.

## 10. Guest / Registered User / Admin Access Levels

### Guest User
A guest user can:

- Access the homepage
- Submit a suspicious URL for checking
- View the phishing detection result
- Read the awareness page

A guest user cannot:

- Save personal scan history
- Access user-only history pages
- Access the administrator dashboard

### Registered User
A registered user can:

- Register a new account
- Log in and log out
- Submit suspicious URLs for checking
- Save scan results under their account
- View their personal scan history
- Access the awareness page

A registered user cannot:

- View other users' histories
- Access the administrator dashboard
- View administrator activity logs

### Admin
An administrator can:

- Log in through the admin login page
- View the admin dashboard
- View all scan history records
- View phishing statistics
- View activity logs

## 11. Security Notes

- Passwords are not stored in plain text. The system uses password hashing through Werkzeug security utilities.
- Flask session security depends on the `SECRET_KEY`, so a strong custom secret key should always be used.
- The default admin account exists only for demo and testing convenience and should not be used unchanged in a real deployment.
- The current input handling includes basic validation, such as checking for empty input, excessively long URLs, spaces in URLs, and invalid schemes.
- The phishing detection logic is rule-based and intended for awareness and educational use. It should not be treated as a complete enterprise-grade phishing defence system.
- SQLite is suitable for development, testing, and academic submission, but a more scalable database would be preferable for large-scale production use.
- The current application runs with debug mode disabled for deployment readiness.

## Public Cloud Hosting with Render

Public cloud hosting means the application runs on an external cloud server. Anyone with the public website link can access the platform, and the developer's own computer does not need to keep the program running.

To deploy this Flask application on Render:

1. Push this project to a GitHub repository.
2. Log in to Render and create a new **Web Service**.
3. Connect the GitHub repository that contains this project.
4. Use the following Render settings:

```text
Build Command:
pip install -r requirements.txt

Start Command:
gunicorn app:app

Environment Variable:
SECRET_KEY = a secure random secret key
```

The `SECRET_KEY` environment variable is used for Flask sessions and CSRF token signing. Use a long, random value and do not commit it to GitHub.

### SQLite Deployment Limitation

The current prototype uses SQLite for demonstration purposes. For production deployment, a persistent managed database such as PostgreSQL is recommended because SQLite database files may not be suitable for long-term cloud persistence.

## 12. Future Improvements

- Add CSRF protection to strengthen form security
- Add email verification during user registration
- Add password reset functionality
- Allow administrators to manage user accounts
- Improve dashboard analytics and reporting
- Add export options for scan history and activity logs
- Expand the rule-based detection logic with more phishing indicators
- Integrate machine learning methods for more advanced detection in future versions
- Add automated unit and integration testing
- Improve deployment readiness with production configuration and stronger environment-based settings
