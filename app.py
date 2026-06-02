import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash

from database import create_connection, initialize_database
from detection import analyze_url, normalize_url


app = Flask(__name__)

# This key is used by Flask sessions and CSRF token signing.
# Set SECRET_KEY in the deployment environment for production.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# Enable CSRF protection for all POST forms.
csrf = CSRFProtect(app)


# Create the database tables when the app starts.
initialize_database()

# Singapore uses UTC+8 all year.
SINGAPORE_TIMEZONE = timezone(timedelta(hours=8))



def get_singapore_time_string():
    """Return the current Singapore time as a database-friendly string."""
    return datetime.now(SINGAPORE_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")



def get_db_connection():
    """Open a database connection and return rows like dictionaries."""
    connection = create_connection()
    connection.row_factory = sqlite3.Row
    return connection



def validate_url_input(user_url):
    """Do simple input validation before analysing the URL."""
    if not user_url:
        return False, "Please enter a URL.", None

    cleaned_url = user_url.strip()

    if not cleaned_url:
        return False, "Please enter a URL.", None

    if len(cleaned_url) > 2048:
        return False, "The URL is too long.", None

    if any(character.isspace() for character in cleaned_url):
        return False, "The URL must not contain spaces.", None

    normalized_url = normalize_url(cleaned_url)
    parsed_url = urlparse(normalized_url)

    if not parsed_url.netloc:
        return False, "Please enter a valid website address.", None

    if parsed_url.scheme and parsed_url.scheme not in ["http", "https"]:
        return False, "Please use a normal website address.", None

    hostname = parsed_url.hostname
    if not hostname:
        return False, "Please enter a valid website address.", None

    return True, "Valid URL.", cleaned_url



def get_client_ip_address():
    """Return the submitter IP address, preferring proxy-forwarded headers."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        for ip_address in forwarded_for.split(","):
            cleaned_ip = ip_address.strip()
            if cleaned_ip:
                return cleaned_ip

    if request.remote_addr:
        return request.remote_addr

    return "Unknown"



def save_scan_result(result, user_id=None, ip_address="Unknown"):
    """Save one scan result into the scans table."""
    explanations_text = json.dumps(result["explanations"])
    recommendations_text = json.dumps(result["recommendations"])
    scanned_at = get_singapore_time_string()

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO scans (user_id, submitted_url, risk_level, score, explanations, recommendations, ip_address, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            result["original_url"],
            result["risk_level"],
            result["total_score"],
            explanations_text,
            recommendations_text,
            ip_address,
            scanned_at,
        ),
    )

    connection.commit()
    connection.close()



def log_activity(action_type, action_details, admin_id=None):
    """Save one activity record into the activity_logs table."""
    created_at = get_singapore_time_string()

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO activity_logs (admin_id, action_type, action_details, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (admin_id, action_type, action_details, created_at),
    )

    connection.commit()
    connection.close()



def get_statistics():
    """Get simple dashboard statistics from the scans table."""
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            COUNT(*) AS total_scans,
            SUM(CASE WHEN risk_level = 'Safe' THEN 1 ELSE 0 END) AS safe_count,
            SUM(CASE WHEN risk_level = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
            SUM(CASE WHEN risk_level = 'High Risk' THEN 1 ELSE 0 END) AS high_risk_count
        FROM scans
        """
    )

    stats_row = cursor.fetchone()
    connection.close()

    return {
        "total_scans": stats_row["total_scans"] or 0,
        "safe_count": stats_row["safe_count"] or 0,
        "suspicious_count": stats_row["suspicious_count"] or 0,
        "high_risk_count": stats_row["high_risk_count"] or 0,
    }



def get_risk_variant(risk_level):
    """Return a Bootstrap-style color name for each risk level."""
    if risk_level == "Safe":
        return "success"
    if risk_level == "Suspicious":
        return "warning"
    return "danger"



def get_score_percent(score):
    """Convert the phishing score into a percentage for the progress bar."""
    max_score_for_display = 10
    score_percent = int((score / max_score_for_display) * 100)

    if score_percent > 100:
        return 100
    if score_percent < 0:
        return 0

    return score_percent



def create_default_admin():
    """
    Create one default admin account if the admins table is empty.
    This is helpful for first-time testing.
    """
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) AS admin_count FROM admins")
    admin_count = cursor.fetchone()["admin_count"]

    if admin_count == 0:
        default_username = "admin"
        default_password = "Admin@123"
        password_hash = generate_password_hash(default_password)
        created_at = get_singapore_time_string()

        cursor.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (default_username, password_hash, created_at),
        )
        connection.commit()

        print("Default admin account created.")
        print("Username: admin")
        print("Password: Admin@123")
        print("Please change these credentials later for better security.")

    connection.close()



def admin_required(view_function):
    """Allow only logged-in administrators to access a route."""
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in as an administrator first.", "warning")
            return redirect(url_for("admin_login"))

        return view_function(*args, **kwargs)

    return wrapped_view



def user_required(view_function):
    """Allow only logged-in users to access a route."""
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to view your scan history.", "warning")
            return redirect(url_for("user_login"))

        return view_function(*args, **kwargs)

    return wrapped_view


@app.route("/")
def home():
    """Show the home page."""
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check_url():
    """Receive the submitted URL, analyse it, save it, and show the result."""
    user_url = request.form.get("url", "")
    is_valid, message, cleaned_url = validate_url_input(user_url)

    if not is_valid:
        flash(message, "danger")
        return redirect(url_for("home"))

    result = analyze_url(cleaned_url)
    ip_address = get_client_ip_address()
    save_scan_result(result, session.get("user_id"), ip_address)
    log_activity(
        "URL Scan",
        f"Scanned URL: {result['original_url']} | Risk level: {result['risk_level']} | Score: {result['total_score']}",
    )

    risk_variant = get_risk_variant(result["risk_level"])
    score_percent = get_score_percent(result["total_score"])

    return render_template(
        "result.html",
        result=result,
        risk_variant=risk_variant,
        score_percent=score_percent,
    )


@app.route("/register", methods=["GET", "POST"])
def user_register():
    """Handle normal user registration."""
    if "user_id" in session:
        return redirect(url_for("user_history"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("user_register.html")

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            connection.close()
            flash("That username is already taken.", "danger")
            return render_template("user_register.html")

        password_hash = generate_password_hash(password)
        created_at = get_singapore_time_string()
        cursor.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, created_at),
        )
        connection.commit()

        user_id = cursor.lastrowid
        connection.close()

        session["user_id"] = user_id
        session["user_username"] = username
        flash("Registration successful. You are now logged in.", "success")
        return redirect(url_for("user_history"))

    return render_template("user_register.html")


@app.route("/login", methods=["GET", "POST"])
def user_login():
    """Handle normal user login."""
    if "user_id" in session:
        return redirect(url_for("user_history"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("user_login.html")

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_username"] = user["username"]
            flash("Login successful.", "success")
            return redirect(url_for("user_history"))

        flash("Invalid username or password.", "danger")

    return render_template("user_login.html")


@app.route("/logout")
def user_logout():
    """Log the normal user out and keep admin sessions intact."""
    session.pop("user_id", None)
    session.pop("user_username", None)
    flash("You have logged out successfully.", "info")
    return redirect(url_for("home"))


@app.route("/history")
@user_required
def user_history():
    """Show the logged-in user's scan history."""
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, submitted_url, risk_level, score, scanned_at
        FROM scans
        WHERE user_id = ?
        ORDER BY scanned_at DESC, id DESC
        """,
        (session["user_id"],),
    )
    scans = cursor.fetchall()
    connection.close()

    return render_template("user_history.html", scans=scans)


@app.route("/history/<int:scan_id>")
@user_required
def user_scan_detail(scan_id):
    """Show one scan detail page for the logged-in user (own records only)."""
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, user_id, submitted_url, risk_level, score,
               explanations, recommendations, ip_address, scanned_at
        FROM scans
        WHERE id = ? AND user_id = ?
        """,
        (scan_id, session["user_id"]),
    )
    scan = cursor.fetchone()
    connection.close()

    if not scan:
        flash("Scan record not found or you do not have permission to view it.", "warning")
        return redirect(url_for("user_history"))

    explanations = json.loads(scan["explanations"])
    recommendations = json.loads(scan["recommendations"])

    try:
        analysis_result = analyze_url(scan["submitted_url"])
        detected_features = analysis_result.get("detected_features", [])
    except Exception:
        detected_features = []

    scan_detail = {
        "id": scan["id"],
        "submitted_url": scan["submitted_url"],
        "ip_address": scan["ip_address"],
        "risk_level": scan["risk_level"],
        "score": scan["score"],
        "detected_features": detected_features,
        "explanations": explanations,
        "recommendations": recommendations,
        "scanned_at": scan["scanned_at"],
    }

    risk_variant = get_risk_variant(scan_detail["risk_level"])
    score_percent = get_score_percent(scan_detail["score"])

    return render_template(
        "user_scan_detail.html",
        scan=scan_detail,
        risk_variant=risk_variant,
        score_percent=score_percent,
    )


@app.route("/awareness")
def awareness():
    """Show the phishing awareness page."""
    return render_template("awareness.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Handle administrator login."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("admin_login.html")

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cursor.fetchone()
        connection.close()

        if admin and check_password_hash(admin["password_hash"], password):
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]

            log_activity(
                "Admin Login",
                f"Administrator '{admin['username']}' logged in.",
                admin["id"],
            )

            flash("Login successful.", "success")
            return redirect(url_for("admin_dashboard"))

        log_activity(
            "Failed Login",
            f"Failed login attempt for username: {username}",
            None,
        )
        flash("Invalid username or password.", "danger")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    """Log the admin out and clear the session."""
    admin_id = session.get("admin_id")
    admin_username = session.get("admin_username")

    if admin_id:
        log_activity(
            "Admin Logout",
            f"Administrator '{admin_username}' logged out.",
            admin_id,
        )

    session.pop("admin_id", None)
    session.pop("admin_username", None)
    flash("You have logged out successfully.", "info")
    return redirect(url_for("home"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Show scan history, activity logs, and simple statistics."""
    # Read filter inputs (GET) for the scan history table.
    query_keyword = request.args.get("q", "", type=str).strip()
    risk_filter = request.args.get("risk", "", type=str).strip()
    username_filter = request.args.get("username", "", type=str).strip()

    # Pagination settings: 10 records per page for both tables.
    scans_per_page = 10
    logs_per_page = 10

    def parse_page(arg_name):
        """Read a page number from the query string. Fall back to 1 on bad input."""
        raw_value = request.args.get(arg_name, "1")
        try:
            page_number = int(raw_value)
        except (TypeError, ValueError):
            page_number = 1
        if page_number < 1:
            page_number = 1
        return page_number

    scan_page = parse_page("scan_page")
    log_page = parse_page("log_page")

    # Build the WHERE clause for scans once, reused by both COUNT and SELECT.
    where_clauses = []
    sql_params = []

    if query_keyword:
        where_clauses.append("scans.submitted_url LIKE ?")
        sql_params.append(f"%{query_keyword}%")

    allowed_risk_levels = {"Safe", "Suspicious", "High Risk"}
    if risk_filter in allowed_risk_levels:
        where_clauses.append("scans.risk_level = ?")
        sql_params.append(risk_filter)

    if username_filter:
        where_clauses.append("users.username LIKE ?")
        sql_params.append(f"%{username_filter}%")

    where_sql = ""
    if where_clauses:
        where_sql = " WHERE " + " AND ".join(where_clauses)

    connection = get_db_connection()
    cursor = connection.cursor()

    # Count total scan records that match the current filters.
    count_sql = f"""
        SELECT COUNT(*) AS total
        FROM scans
        LEFT JOIN users ON scans.user_id = users.id
        {where_sql}
    """
    cursor.execute(count_sql, sql_params)
    scan_total_records = cursor.fetchone()["total"] or 0
    scan_total_pages = max(1, (scan_total_records + scans_per_page - 1) // scans_per_page)
    if scan_page > scan_total_pages:
        scan_page = scan_total_pages
    scan_offset = (scan_page - 1) * scans_per_page

    # Fetch the current page of scans.
    select_sql = f"""
        SELECT scans.id, scans.submitted_url, scans.ip_address, scans.risk_level, scans.score,
               scans.scanned_at, users.username AS owner_username
        FROM scans
        LEFT JOIN users ON scans.user_id = users.id
        {where_sql}
        ORDER BY scans.scanned_at DESC, scans.id DESC
        LIMIT ? OFFSET ?
    """
    cursor.execute(select_sql, sql_params + [scans_per_page, scan_offset])
    scans = cursor.fetchall()

    # Count total activity logs (no filters apply to logs).
    cursor.execute("SELECT COUNT(*) AS total FROM activity_logs")
    log_total_records = cursor.fetchone()["total"] or 0
    log_total_pages = max(1, (log_total_records + logs_per_page - 1) // logs_per_page)
    if log_page > log_total_pages:
        log_page = log_total_pages
    log_offset = (log_page - 1) * logs_per_page

    cursor.execute(
        """
        SELECT id, admin_id, action_type, action_details, created_at
        FROM activity_logs
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (logs_per_page, log_offset),
    )
    logs = cursor.fetchall()

    connection.close()

    stats = get_statistics()

    template_context = dict(
        scans=scans,
        logs=logs,
        stats=stats,
        q=query_keyword,
        risk=risk_filter,
        username=username_filter,
        scan_page=scan_page,
        scan_total_pages=scan_total_pages,
        log_page=log_page,
        log_total_pages=log_total_pages,
    )

    # If the request asks for a partial (used by AJAX pagination), only
    # return the relevant table+pagination fragment instead of the full page.
    partial_section = request.args.get("partial", "").strip()
    if partial_section == "scans":
        return render_template(
            "partials/admin_scan_history_table.html", **template_context
        )
    if partial_section == "logs":
        return render_template(
            "partials/admin_activity_logs_table.html", **template_context
        )

    return render_template("admin_dashboard.html", **template_context)


@app.route("/admin/scan/<int:scan_id>")
@admin_required
def admin_scan_detail(scan_id):
    """Show the full details for one stored scan record."""
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT scans.id, scans.user_id, scans.submitted_url, scans.ip_address,
               scans.risk_level, scans.score, scans.explanations,
               scans.recommendations, scans.scanned_at,
               users.username AS owner_username
        FROM scans
        LEFT JOIN users ON scans.user_id = users.id
        WHERE scans.id = ?
        """,
        (scan_id,),
    )
    scan = cursor.fetchone()
    connection.close()

    if not scan:
        flash("Scan record not found.", "warning")
        return redirect(url_for("admin_dashboard"))

    explanations = json.loads(scan["explanations"])
    recommendations = json.loads(scan["recommendations"])

    try:
        analysis_result = analyze_url(scan["submitted_url"])
        detected_features = analysis_result.get("detected_features", [])
    except Exception:
        detected_features = []

    scan_detail = {
        "id": scan["id"],
        "owner_username": scan["owner_username"] or "Guest",
        "submitted_url": scan["submitted_url"],
        "ip_address": scan["ip_address"],
        "risk_level": scan["risk_level"],
        "score": scan["score"],
        "detected_features": detected_features,
        "explanations": explanations,
        "recommendations": recommendations,
        "scanned_at": scan["scanned_at"],
    }

    risk_variant = get_risk_variant(scan_detail["risk_level"])
    score_percent = get_score_percent(scan_detail["score"])

    return render_template(
        "admin_scan_detail.html",
        scan=scan_detail,
        risk_variant=risk_variant,
        score_percent=score_percent,
    )



create_default_admin()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting phishing detection platform at http://127.0.0.1:{port}")
    serve(app, host="0.0.0.0", port=port)
