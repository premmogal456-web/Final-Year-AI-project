from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from threat_detector import analyze_logs
from database import register_user, get_user, update_password, delete_user, get_connection
import os
import csv
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# ---------- HOME ----------
@app.route("/")
def home():
    if "user" in session:
        return render_template("index.html")
    return redirect(url_for("login"))


# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # PASSWORD RULE
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8}$'

        if not re.match(pattern, password):
            flash("Password must be exactly 8 characters and include uppercase, lowercase, number, and special symbol.", "error")
            return render_template("register.html")

        if get_user(username):
            flash("Username already exists", "error")
            return render_template("register.html")

        register_user(username, password)
        flash("Account created successfully. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = get_user(username)

        if not user:
            flash("Username does not exist", "error")
        elif user[2] != password:
            flash("Password is incorrect", "error")
        else:
            session["user"] = username
            return redirect(url_for("home"))

    return render_template("login.html")


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ---------- SETTINGS ----------
@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("settings.html")


# ---------- CHANGE PASSWORD ----------
@app.route("/change_password", methods=["POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    old_password = request.form["old_password"]
    new_password = request.form["new_password"]

    # PASSWORD RULE
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8}$'

    if not re.match(pattern, new_password):
        flash("New password must be exactly 8 characters and include uppercase, lowercase, number, and special symbol.", "error")
        return redirect(url_for("settings"))

    user = get_user(username)

    if user and user[2] == old_password:
        update_password(username, new_password)
        flash("Password updated successfully", "success")
    else:
        flash("Old password incorrect", "error")

    return redirect(url_for("settings"))


# ---------- DELETE ACCOUNT ----------
@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    password = request.form["password"]

    user = get_user(username)

    if user and user[2] == password:
        delete_user(username)
        session.pop("user", None)
        flash("Account deleted successfully", "success")
        return redirect(url_for("login"))
    else:
        flash("Password incorrect", "error")
        return redirect(url_for("settings"))


# ---------- ANALYZE ----------
@app.route("/analyze", methods=["POST"])
def analyze():
    if "user" not in session:
        return redirect(url_for("login"))

    file = request.files["logfile"]

    if file.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("home"))

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    results, stats, total_logs, most_dangerous_ip, threat_score = analyze_logs(filepath)

    return render_template(
        "results.html",
        results=results,
        stats=stats,
        total_logs=total_logs,
        most_dangerous_ip=most_dangerous_ip,
        threat_score=round(threat_score, 2)
    )


# ---------- REPORTS ----------
@app.route("/reports")
def reports():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT ip, log, threat FROM logs")
    data = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_attacks = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return render_template("reports.html", data=data, total_attacks=total_attacks)


# ---------- EXPORT CSV ----------
@app.route("/export")
def export():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip, log, threat FROM logs")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    file_path = "logs_report.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Log", "Threat"])
        writer.writerows(rows)

    return send_file(file_path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)