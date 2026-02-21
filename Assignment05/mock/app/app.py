from flask import Flask, flash, redirect, render_template, request, session, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session

import sqlite3 as sql
import os


APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
limiter = Limiter(get_remote_address, app=app, default_limits=["500 per hour"])
Session(app)


# Login page
@app.route("/", methods=["GET"])
@limiter.exempt
def home():
    return render_template("login.html")

# LOOK HERE!
# Login request handler
@app.route("/login", methods=["POST"])
@limiter.limit("1/second", override_defaults=False)
def login():
    # grab the password from the request
    password = request.form["password"]
    # No stacked queries are allowed :( This app is secure!
    if ";" in password:
        flash("This looked like an SQL injection. Stacked queries are insecure!")
        return render_template("login.html"), 403
    if " " in password:
        flash("This looked like an SQL injection. Passwords are not supposed to have blank spaces!")
        return render_template("login.html"), 403

    # Hmm... This is safe right? RIGHT?!
    query = f"SELECT * FROM users WHERE username = 'user' AND password = '{password}'"
    # Get a connection to the database
    cursor = con.cursor()
    # Execute the query
    res = cursor.execute(query)
    # If result is empty, then the password is wrong
    if res.fetchone() is None:
        flash("wrong password!")
        return render_template("login.html"), 403

    # Set the session and redirect to the dashboard
    session["logged_in"] = True
    return redirect("/dashboard#user")


@app.route("/dashboard", methods=["GET"])
@limiter.exempt
def dashboard():
    # Check if the user is logged in
    if not session.get("logged_in"):
        flash("NOPE! :)")
        return render_template("login.html"), 403
    return render_template("dashboard.html")


# LOOK HERE TOO!
@app.route("/search", methods=["POST"])
@limiter.limit("1/second", override_defaults=False)
def search():
    # Check if the user is logged in
    if not session.get("logged_in"):
        flash("NOPE! :)")
        return render_template("login.html"), 403
    # Get the search query
    name = request.form["item_name"]

    # Mo stacked queries are allowed :( This app is secure!
    if ";" in name:
        flash("This looked like an SQL injection. Stacked queries are insecure!")
        return render_template("dashboard.html"), 403

    query = f"SELECT name,category,price FROM items WHERE name = '{name}'"
    # Get a connection to the database
    cursor = con.cursor()
    # Execute the query
    res = cursor.execute(query)
    # Get the results
    results = res.fetchall()
    if not results:
        return render_template("dashboard.html", noitem=name)

    results = results[0]
    # Render the results
    return render_template("dashboard.html", results=results)

@app.route("/admin", methods=["GET", "POST"])
@limiter.exempt
def admin():
    query = "SELECT * FROM users WHERE username = 'superadmin'"
    # Get a connection to the database
    cursor = con.cursor()
    # Execute the query
    res = cursor.execute(query).fetchone()
    admin_pass = res[2]
    admin_cookie = request.cookies.get('admin')
    
    resp = None
    if request.method == "GET":
        if admin_cookie != admin_pass: return render_template("admin_login.html"), 403
        filename = request.args.get('show')
        contents = None

        if filename and "." not in filename and os.path.isfile("%s/%s.txt" % (APP_ROOT, filename)):
            with open("%s/%s.txt" % (APP_ROOT, filename), "r") as fp:
                contents = fp.read()
        resp = make_response(render_template("admin_dashboard.html", contents = contents, filename = filename)) 
    elif request.method == "POST":
        password = request.form["password"]
        if password != admin_pass: return render_template("admin_login.html"), 403
        resp = make_response(render_template("admin_dashboard.html"))
        resp.set_cookie("admin", admin_pass)
    else: return render_template("admin_login.html"), 403

    return resp

@app.route("/files", methods = ["GET"])
def files():
    file_dir = os.path.join(APP_ROOT, "files")
    files = os.listdir(file_dir)
    return render_template("files.html", files = files)

@app.route("/go", methods = ["GET"])
def goto():
    to = request.args.get('to')
    return redirect(to)

@app.route("/logout", methods = ["GET"])
def logout():
    to = request.args.get('to')
    resp = make_response(redirect("/admin")) 
    resp.set_cookie('admin', '', expires = 0), 302
    return resp

@app.after_request
def add_headers(response):
    response.headers["Content-Security-Policy"] = "script-src 'nonce-1337x0xyz'"
    return response

if __name__ == "__main__":
    con = sql.connect("./db/database.db", check_same_thread=False) # Connect to the database
    debug = True if os.getenv("FLASK_DEBUG") == "TRUE" else False # Run the app
    app.run(debug=debug, host="0.0.0.0", port=8080)
