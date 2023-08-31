from flask import render_template, request, redirect, url_for, session, make_response, flash
from pydiscovery import app
from pydiscovery.tasks import perform_discovery
from pydiscovery.models import DiscoveryResult, User
import bcrypt
from pydiscovery import db 
import sqlite3
import pydiscovery.ping_sweep, pydiscovery.tcp_scan, pydiscovery.arp_scan, pydiscovery.snmp_discovery
from datetime import datetime
import csv
from werkzeug.utils import secure_filename
import os
from pydiscovery.forms import LoginForm, RegistrationForm, EmailChangeForm, PasswordChangeForm
from ldap3 import Server, Connection

# Helper function to create the user table if it doesn't exist
def create_user_table():
    conn = sqlite3.connect("./instance/app.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    

    conn.commit()
    conn.close()

create_user_table()

def create_discovery_result_table():
    conn = sqlite3.connect("./instance/app.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovery_result (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME,
            method TEXT,
            ip_range TEXT,
            result TEXT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    """)
    conn.commit()
    conn.close()
create_discovery_result_table()


# Function to check if the provided credentials are valid
def is_valid_credentials(username, password):
    conn = sqlite3.connect("./instance/app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM user WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()

    # Check if the username exists and compare the hashed passwords
    return result and bcrypt.checkpw(password.encode("utf-8"), result[0])


@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            auth_method = form.auth_method.data
            username = form.username.data
            password = form.password.data

            if auth_method == "local":

                # Check if the provided username and password are valid
                if is_valid_credentials(username, password):
                    session["username"] = username  # Store the username in the session
                    return redirect(url_for("dashboard"))

                error = "Invalid credentials. Please try again."
                return render_template("login.html", error=error, form=form)
    

            elif auth_method == "ldap":
                ldap_server = Server('ldap://localhost')
                try:
                    with Connection(ldap_server, user=username, password=password, auto_bind=True) as conn:
                        # Successful LDAP authentication
                        session["username"] = username
                        return redirect(url_for("dashboard"))
                except Exception as e:
                    # LDAP authentication failed
                    error = "LDAP authentication failed. Please try again."
                    flash("LDAP authentication failed", "error")
                    print(e)
                    print("ldap fail")
                    return render_template("login.html", error=error, form=form)

    # If the user is already logged in, redirect them to the dashboard
    if "username" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)

@app.route("/create_user", methods=["GET", "POST"])
def create_user():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Get values entered by the user
        username = form.username.data
        email = form.email.data  
        password = form.password.data

        # Check if the username already exists in the database
        conn = sqlite3.connect("./instance/app.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            error = "Username already exists. Please choose a different username."
            return render_template("create_user.html", error=error)

        # Hash the password before storing it in the database
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Insert the new user into the database
        try:
            cursor.execute("INSERT INTO user (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
            conn.commit()
            conn.close()
            #session["username"] = username  # Store the username in the session
            flash("User created successfuly! You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.Error as e:
            error = "Error creating the user. Please try again."
            return render_template("create_user.html", error=error, form=form)
    return render_template("create_user.html", form=form)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # Check if the user is logged in by verifying the session
    if "username" in session:
        username = session["username"]

        if request.method == "POST":
            ip_input = request.form["ip_input"]
            #method_input = "ping"
            method_input = request.form["method_input"]
            scheduled_time_str = request.form.get("scheduled_time")

            if method_input == "ping":
                active_hosts = pydiscovery.ping_sweep.ping_scan(ip_input)
                result_text = '\n'.join(active_hosts)
            elif method_input == "port":
                ports_input = request.form["ports_input"]
                try:
                    ports = [int(p) for p in ports_input.split(",")]
                    active_hosts = pydiscovery.tcp_scan.tcp_syn_scan(ip_input, ports)
                    result_text = ""
                    for ip, ports in active_hosts.items():
                        result_text += f"IP: {ip}, Open Ports: {ports}\n"
                    print(active_hosts)

                except:
                    flash("Please enter ports as comma-seperated. E.g: '22, 23'")
            elif method_input == "arp":
                active_hosts = pydiscovery.arp_scan.arp_scan(ip_input)
                result_text = '\n'.join(active_hosts)
            elif method_input == "snmp":
                active_hosts = pydiscovery.snmp_discovery.snmp_scan(ip_input)
                result_text = '\n'.join(active_hosts)
            else:
                active_hosts = []  # Default case
                result_text = ""

            if scheduled_time_str:
                scheduled_time = datetime.strptime(scheduled_time_str, "%Y-%m-%dT%H:%M")
                print(scheduled_time)
                current_time = datetime.now()
                print(current_time)
            else:
                scheduled_time_str = datetime.utcnow

            if scheduled_time_str != datetime.utcnow:
                if scheduled_time > current_time:
                    if request.form["ports_input"]:
                        ports_input = request.form["ports_input"]
                    else:
                        ports_input = ""
                    perform_discovery.apply_async(args=(method_input, ip_input, ports_input, username), eta=scheduled_time)
                    flash("Discovery task scheduled successfully!", "info")
                    print("scheduled successfuly")
                else:
                    flash("Scheduled time must be in the future.", "error")


            # Get the current user based on the logged-in username
            current_user = User.query.filter_by(username=username).first()
            scheduled_time = None
            # Save the result to the database
            flash("Discovery task is in progress. Please check the results later.", "info")
            try:
                if scheduled_time:
                    discovery_result = DiscoveryResult(timestamp=scheduled_time, method=method_input, ip_range=ip_input, result=result_text, user=current_user)
                else:
                    discovery_result = DiscoveryResult(method=method_input, ip_range=ip_input, result=result_text, user=current_user)
                db.session.add(discovery_result)
                db.session.commit()
                return render_template("result.html", username=username, active_hosts=active_hosts, method_input=method_input)
            except Exception as e:
                print(e)
                flash("Apologies. Something went wrong.", 'error')

            # Add method_input so that the if condition in result works 
                        
        return render_template("dashboard.html", username=username)

    # If the user is not logged in, redirect them to the login page
    return redirect(url_for("login"))

@app.route("/home")
def home():
    username = session["username"]
    current_user = User.query.filter_by(username=username).first()
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    last_discovery = DiscoveryResult.query.filter_by(user_id=current_user.id).order_by(DiscoveryResult.timestamp.desc()).first()
    return render_template("home.html", current_datetime=current_datetime, username=username, last_discovery=last_discovery)

@app.route("/results")
def results():
    username = session["username"]
    current_user = User.query.filter_by(username=username).first()

    # Create a query object for DiscoveryResult
    query = db.session.query(DiscoveryResult).filter_by(user_id=current_user.id)
    
    # Retrieve all saved discovery results from the database
    filter_method = request.args.get("method", default="all")
    if filter_method != "all":
        query = query.filter_by(method=filter_method)

    all_results = query.all()
    
    return render_template("results.html", username=username, all_results=all_results, current_user=current_user)

@app.route("/download_results_csv")
def download_results_csv():
    all_results = DiscoveryResult.query.all()

    csv_data = []
    csv_data.append(["Method", "IP Range", "Result", "Timestamp"])
    for result in all_results:
        timestamp_str = result.timestamp.strftime('%Y-%m-%d %H:%M:%S')  # Convert datetime to string
        csv_data.append([result.method, result.ip_range, result.result, timestamp_str])

    response = make_response('\n'.join([','.join(row) for row in csv_data]))
    response.headers["Content-Disposition"] = "attachment; filename=discovery_results.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/delete_results', methods=['POST'])
def delete_results():
    if request.method == 'POST':
        selected_results = request.form.getlist('selected_results')
        selected_results = [int(result_id) for result_id in selected_results]

        # Delete selected results from the database
        for result_id in selected_results:
            result = DiscoveryResult.query.get(result_id)
            if result:
                db.session.delete(result)

        db.session.commit()

    return redirect(url_for('results'))

@app.route("/logout")
def logout():
    # Clear the session and log the user out
    session.pop("username", None)
    return redirect(url_for("login"))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 megabytes

def allowed_file(filename):
    extension = filename.rsplit('.', 1)[1].lower()
    return '.' in filename and extension in ALLOWED_EXTENSIONS

@app.route("/user", methods=["GET", "POST"])
def user():
    if "username" in session:
        username = session["username"]
        user = User.query.filter_by(username=username).first()
        email_change_form = EmailChangeForm()  
        password_change_form = PasswordChangeForm()
        error = None  

        if request.method == "POST":
            if "file" in request.files:
                file = request.files["file"]
                if file and allowed_file(file.filename):
                    if file.content_length > MAX_FILE_SIZE:
                        error = "File size exceeds the limit of 2 megabytes."
                    else:
                        filename = secure_filename(file.filename)
                        try:
                            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                        except FileNotFoundError:
                            flash("Selected file doesn't exist.")
                        user.account_picture = filename
                        db.session.commit()
                        error = None
                else:
                    error = "Invalid file format. Allowed formats: png, jpg, jpeg, gif."

            if email_change_form.validate_on_submit():
                new_email = email_change_form.email.data
                user.email = new_email
                db.session.commit()
                flash("Email address changed successfully!", "success")
                return redirect(url_for("user"))
            else:
                flash("Failed to change, please try again.", "error")

            if password_change_form.validate_on_submit():
                current_password = password_change_form.current_password.data
                new_password = password_change_form.new_password.data
                confirm_new_password = password_change_form.confirm_new_password.data

                # Check if the current password matches the one in the database
                if bcrypt.checkpw(current_password.encode('utf-8'), user.password):
                    # Hash the new password before storing it in the database
                    hashed_new_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
                    user.password = hashed_new_password
                    db.session.commit()
                    flash("Password changed successfully!", "success")
                else:
                    error = "Current password is incorrect."

            return render_template("user.html", username=username, user=user, email_change_form=email_change_form, password_change_form=password_change_form, error=error)

        return render_template("user.html", username=username, user=user, email_change_form=email_change_form, password_change_form=password_change_form, error=error)

    return redirect(url_for("login"))


@app.route("/help")
def help():
    if "username" in session:
        username = session["username"]
    return render_template("help.html", username=username)
