from flask import Flask, request, redirect, session, render_template
from cs50 import SQL
from flask_session import Session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required

db = SQL("sqlite:///pass.db")

app = Flask(__name__)
#app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] =  "filesystem"
Session(app)
app.config["TEMPLATES_AUTO_RELOAD"] = True


def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET","POST"])
@login_required
def index():
  if not session.get("user_id"):
    return redirect("/login")
  if request.method == "POST":
    account = request.form.get("account")
    username = request.form.get("username")
    password = request.form.get("password")

    if not request.form.get("username"):
      return redirect("/error")

    # Ensure password was submitted
    elif not request.form.get("password"):
      return redirect("/error")
    
    elif not request.form.get("account"):
      return redirect("/error")
    
    #hash = generate_password_hash(
           # password, method="pbkdf2:sha256", salt_length=8
        #)
      
    try:  
      test = db.execute("INSERT INTO passwords(pid,account, username, hash) VALUES(?,?,?,?)",session["user_id"],account,username,password)
      if not test:
        return redirect("/error")
    except:
      return redirect("/error")
    
    return redirect("/")
    
  else:
    if not session.get("user_id"):
      return redirect("/login")
    
    rows = db.execute("SELECT * FROM passwords WHERE pid=?",session["user_id"])
    
    return render_template("index.html",rows=rows)
    
    


@app.route("/login", methods=["GET", "POST"])
def login():
  session.clear()
  if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")
    print("Entered Post Loop")
    
    if not request.form.get("username"):
      return redirect("/error")

    # Ensure password was submitted
    elif not request.form.get("password"):
      return redirect("/error")
    
    
        
    
    rows = db.execute("SELECT * FROM users WHERE username = ?",username)
    
    if len(rows) != 1:
      return redirect("/error")
    
    if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
      return redirect("/error")
      
    else:
      session["user_id"] = rows[0]["id"]
      return redirect("/")
  
  else:
    return render_template("login.html")  
    
    
@app.route("/register", methods=["GET","POST"])
def register():
  if request.method == "POST":
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    rows = db.execute("SELECT * FROM users WHERE username = ?", username)

    # Ensure the username was submitted
    if not username:
        return redirect("/error")
    # Ensure the username doesn't exists
    elif len(rows) != 0:
        return redirect("/error")

    # Ensure password was submitted
    elif not password:
        return redirect("/error")

    # Ensure confirmation password was submitted
    elif not request.form.get("confirmation"):
        return redirect("/error")

    # Ensure passwords match
    elif not password == confirmation:
        return redirect("/error")

    else:
        # Generate the hash of the password
        hash = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=8
        )
        # Insert the new user
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash,
        )
        # Redirect user to home page
        return redirect("/")

  # User reached route via GET (as by clicking a link or via redirect)
  else:
      return render_template("register.html")

@app.route("/edit", methods=["GET","POST"])
def edit():
  if not session.get("user_id"):
    return redirect("/login")
  
  if request.method == "POST":
    if request.form['submit_button'] == "Edit":
      account = request.form.get("account")
      
      if not account:
        return redirect("/error")
        
      return render_template("edit-acc.html", account = account)
      
    elif request.form['submit_button'] == "Delete":
      account = request.form.get("account")
      if not account:
        return redirect("/error")
      db.execute("DELETE FROM passwords WHERE account=? AND pid=?",account,session["user_id"])
      return redirect("/")
      
    else:
      return redirect("/error")
    
    
  else:
    rows = db.execute("SELECT account FROM passwords WHERE pid=?",session["user_id"])
    
    return render_template("edit.html", rows=rows)
  

@app.route("/edit-acc", methods=["POST"])
def edit_acc():
  if not session.get("user_id"):
    return redirect("/login")
  
  if request.method == "POST":
    
    account = request.form.get("account")
    username = request.form.get("username")
    password = request.form.get("password")

    if not request.form.get("username"):
      return redirect("/error")

    # Ensure password was submitted
    elif not request.form.get("password"):
      return redirect("/error")
    
    elif not request.form.get("account"):
      return redirect("/error")
    
    
    db.execute("UPDATE passwords SET username=?, hash=? WHERE account=? AND pid=?",username,password,account,session["user_id"])
    return redirect("/")
  
  else:
    return redirect("/error")

@app.route("/error")
def error():
  return render_template("error.html")
  
  
@app.route("/logout")
def logout():
    session.clear()
    return render_template("login.html")