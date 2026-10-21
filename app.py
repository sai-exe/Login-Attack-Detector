import csv
import hashlib
import hmac
import io
from datetime import datetime, timedelta
from pathlib import Path
from flask import session

from flask import (
    Flask, render_template, make_response,
    redirect, url_for, request, flash
)
from detector import analyze_logs

app = Flask(__name__)

app.secret_key = "login-detector-local-demo-key"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB

# ---------------------------------------------------------------------------
# Demo credentials — stored as SHA-256 digests, never as plaintext.
# These are clearly labelled educational accounts only.
# ---------------------------------------------------------------------------
_DEMO_ACCOUNTS = {
    "demo":  hashlib.sha256(b"Demo@1234").hexdigest(),
    "admin": hashlib.sha256(b"Admin@5678").hexdigest(),
}


def _sha256(password: str) -> str:
    """Return the SHA-256 hex digest of a password string."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _append_login_record(username: str, ip: str, status: str) -> None:
    """
    Safely append a single validated login record to the active CSV log.

    Validates all fields before writing so a bad call cannot corrupt the
    log file.  Never writes password data.
    """
    # Validate inputs before touching the file.
    username = (username or "").strip()[:128]   # cap length for safety
    ip = (ip or "unknown").strip()[:45]          # max IPv6 string length

    if not username or not ip:
        raise ValueError("Username and IP address are required.")

    status = status.strip().upper()
    if status not in {"SUCCESS", "FAILED"}:
        raise ValueError("Status must be SUCCESS or FAILED.")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with LOG_FILE.open("a+", newline="", encoding="utf-8") as file:
        # Ensure the previous line ends with a newline.
        file.seek(0, 2)
        file_size = file.tell()
        if file_size > 0:
            file.seek(file_size - 1)
            if file.read(1) not in {"\n", "\r"}:
                file.write("\n")
        file.seek(0, 2)
        csv.writer(file).writerow([timestamp, username, ip, status])

LOG_FILE = Path("data/login_logs.csv")
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_TIME_WINDOW = 60

@app.route("/")
def dashboard():
    try:
       results = analyze_logs(
    max_attempts=session.get("max_attempts", DEFAULT_MAX_ATTEMPTS),
    time_window=session.get("time_window", DEFAULT_TIME_WINDOW)
)
       return render_template("index.html", data=results, error=None)

    except (ValueError, OSError) as error:
        return render_template(
            "index.html",
            data=None,
            error=str(error)
        )

@app.route("/attack-detection")
def attack_detection():
    try:
        results = analyze_logs(
    max_attempts=session.get("max_attempts", DEFAULT_MAX_ATTEMPTS),
    time_window=session.get("time_window", DEFAULT_TIME_WINDOW)
)
        return render_template(
            "attack_detection.html",
            data=results,
            error=None
        )
    except (ValueError, OSError) as error:
        return render_template(
            "attack_detection.html",
            data=None,
            error=str(error)
        )    

@app.route("/log-analysis")
def log_analysis():
    try:
        results = analyze_logs(
    max_attempts=session.get("max_attempts", DEFAULT_MAX_ATTEMPTS),
    time_window=session.get("time_window", DEFAULT_TIME_WINDOW)
)

        return render_template(
            "log_analysis.html",
            data=results,
            error=None
        )

    except (ValueError, OSError) as error:
        return render_template(
            "log_analysis.html",
            data=None,
            error=str(error)
        )

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        try:
            max_attempts = int(request.form.get("max_attempts", "5"))
            time_window = int(request.form.get("time_window", "60"))

            if not 1 <= max_attempts <= 100:
                raise ValueError("Attempts must be between 1 and 100.")

            if not 1 <= time_window <= 3600:
                raise ValueError(
                    "Time window must be between 1 and 3600 seconds."
                )

            session["max_attempts"] = max_attempts
            session["time_window"] = time_window

            flash("Detection settings saved successfully.")
            return redirect(url_for("settings"))

        except ValueError as error:
            return render_template(
                "settings.html",
                max_attempts=request.form.get("max_attempts", "5"),
                time_window=request.form.get("time_window", "60"),
                error=str(error)
            )

    return render_template(
        "settings.html",
        max_attempts=session.get("max_attempts", DEFAULT_MAX_ATTEMPTS),
        time_window=session.get("time_window", DEFAULT_TIME_WINDOW),
        error=None
    )
    
@app.route("/simulate/<scenario>")
def simulate(scenario):
    if scenario not in {"normal", "attack"}:
        return "Invalid simulation type", 400

    now = datetime.now()

    if scenario == "attack":
        # Simulate five failed login attempts from one IP.
        records = [
            [
                (now + timedelta(seconds=i * 5)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "admin",
                "192.168.1.99",
                "FAILED",
            ]
            for i in range(5)
        ]

    else:
        # Simulate three successful logins.
        records = [
            [
                (now + timedelta(minutes=i * 3)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "demo_user",
                "192.168.1.98",
                "SUCCESS",
            ]
            for i in range(3)
        ]

    # Append records safely to the existing CSV file.
    with LOG_FILE.open("a+", newline="", encoding="utf-8") as file:
        file.seek(0, 2)
        file_size = file.tell()

        if file_size > 0:
            file.seek(file_size - 1)
            last_character = file.read(1)

            if last_character not in {"\n", "\r"}:
                file.write("\n")

        file.seek(0, 2)
        writer = csv.writer(file)
        writer.writerows(records)

    return redirect(url_for("dashboard"))

@app.route("/reset-demo")
def reset_demo():
    sample_logs = [
        ["timestamp", "username", "ip_address", "status"],
        ["2026-10-15 10:00:01", "admin", "192.168.1.10", "FAILED"],
        ["2026-10-15 10:00:05", "admin", "192.168.1.10", "FAILED"],
        ["2026-10-15 10:00:10", "admin", "192.168.1.10", "FAILED"],
        ["2026-10-15 10:00:15", "admin", "192.168.1.10", "FAILED"],
        ["2026-10-15 10:00:20", "admin", "192.168.1.10", "FAILED"],
        ["2026-10-15 10:01:00", "user1", "192.168.1.20", "SUCCESS"],
        ["2026-10-15 10:02:00", "user2", "192.168.1.30", "SUCCESS"],
    ]

    with LOG_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(sample_logs)

    return redirect(url_for("dashboard"))

@app.route("/download-report")
def download_report():
    results = analyze_logs(
        max_attempts=session.get(
            "max_attempts", DEFAULT_MAX_ATTEMPTS
        ),
        time_window=session.get(
            "time_window", DEFAULT_TIME_WINDOW
        )
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "IP Address",
        "Failed Attempts",
        "Risk Score",
        "Risk Level",
    ])

    for alert in results["alerts"]:
        writer.writerow([
            alert["ip"],
            alert["attempts"],
            alert["risk_score"],
            alert["risk"],
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = (
        "attachment; filename=security_report.csv"
    )

    return response

@app.route("/upload-csv", methods=["POST"])
def upload_csv():
    if "file" not in request.files:
        flash("Please select a CSV file.")
        return redirect(url_for("dashboard"))

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        flash("Please select a file.")
        return redirect(url_for("dashboard"))

    if not uploaded_file.filename.lower().endswith(".csv"):
        flash("Only CSV files are allowed.")
        return redirect(url_for("dashboard"))

    try:
        import csv
        import io
        from datetime import datetime
        from pathlib import Path

        # Read the uploaded file.
        content = uploaded_file.stream.read().decode("utf-8-sig")

        reader = csv.DictReader(io.StringIO(content))

        required_columns = {
            "timestamp", "username", "ip_address", "status"
        }

        if not reader.fieldnames:
            raise ValueError("The CSV file is empty.")

        reader.fieldnames = [
            name.strip() for name in reader.fieldnames
        ]

        # Reject duplicate column names.
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("The CSV contains duplicate column names.")

        if not required_columns.issubset(set(reader.fieldnames)):
            raise ValueError(
                "CSV must contain timestamp, username, "
                "ip_address, and status columns."
            )

        rows = list(reader)

        if not rows:
            raise ValueError("The CSV contains no login records.")

        normalized_rows = []

        # Validate every record before modifying the active log file.
        for line_number, row in enumerate(rows, start=2):
            if None in row:
                raise ValueError(
                    f"Line {line_number}: unexpected extra CSV fields."
                )

            timestamp = (row.get("timestamp") or "").strip()
            username = (row.get("username") or "").strip()
            ip_address = (row.get("ip_address") or "").strip()
            status = (row.get("status") or "").strip().upper()

            try:
                parsed_timestamp = datetime.strptime(
                    timestamp, "%Y-%m-%d %H:%M:%S"
                )
            except ValueError as error:
                raise ValueError(
                    f"Line {line_number}: invalid timestamp format."
                ) from error

            if not username or not ip_address:
                raise ValueError(
                    f"Line {line_number}: username and IP address "
                    "are required."
                )

            if status not in {"SUCCESS", "FAILED"}:
                raise ValueError(
                    f"Line {line_number}: status must be "
                    "SUCCESS or FAILED."
                )

            normalized_rows.append([
                parsed_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                username,
                ip_address,
                status,
            ])

        # Build the candidate CSV in memory.
        output = io.StringIO(newline="")
        writer = csv.writer(output)

        writer.writerow([
            "timestamp", "username", "ip_address", "status"
        ])
        writer.writerows(normalized_rows)

        candidate_content = output.getvalue()

        # Validate the candidate file before replacing active logs.
        candidate_file = Path(LOG_FILE).with_suffix(".tmp")

        try:
            candidate_file.write_text(
                candidate_content, encoding="utf-8", newline=""
            )

            analyze_logs(
                log_file=candidate_file,
                max_attempts=session.get(
                    "max_attempts", DEFAULT_MAX_ATTEMPTS
                ),
                time_window=session.get(
                    "time_window", DEFAULT_TIME_WINDOW
                ),
            )

            # Replace active logs only after successful validation.
            candidate_file.replace(LOG_FILE)

        finally:
            # Remove the temporary file if it still exists.
            if candidate_file.exists():
                candidate_file.unlink()

        flash(
    f"Successfully uploaded and analyzed "
    f"{len(normalized_rows)} login records.",
    "success"
)

    except (ValueError, UnicodeDecodeError, OSError) as error:
        flash(f"Upload failed: {error}", "error")

    return redirect(url_for("dashboard"))


@app.route("/login-simulator", methods=["GET", "POST"])
def login_simulator():
    """
    Login Simulator — educational demo page.

    Accepts two hardcoded demo accounts and records every attempt
    (SUCCESS or FAILED) to the shared login log so the detection
    engine can analyse them alongside existing data.
    """
    result = None   # dict with keys: status ("success"|"error"), message

    if request.method == "POST":
        # Read form values; strip but never log the raw password.
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        # Use server-observed IP address — never trust client-supplied headers.
        client_ip = request.remote_addr or "unknown"

        # Authenticate: constant-time comparison to avoid timing oracle.
        stored_hash = _DEMO_ACCOUNTS.get(username.lower())
        if stored_hash is not None and hmac.compare_digest(
            _sha256(password), stored_hash
        ):
            status = "SUCCESS"
            result = {
                "status": "success",
                "message": (
                    "Login successful. Welcome, "
                    + username
                    + "! This attempt has been logged."
                ),
            }
        else:
            status = "FAILED"
            result = {
                "status": "error",
                # Generic message — does not reveal whether username or
                # password was incorrect.
                "message": (
                    "Invalid credentials. Please check your username "
                    "and password and try again."
                ),
            }

        # Append the attempt to the shared log regardless of outcome.
        try:
            _append_login_record(
                username=username if username else "unknown",
                ip=client_ip,
                status=status,
            )
        except (OSError, ValueError):
            # Logging failure should not expose an error to the user.
            pass

    return render_template(
        "login_simulator.html",
        result=result,
    )


if __name__ == "__main__":
    app.run(debug=True)