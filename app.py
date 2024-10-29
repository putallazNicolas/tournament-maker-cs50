import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from random import shuffle

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Library to use SQLite database
db = SQL("sqlite:///tournaments.db")

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    tournaments = db.execute("SELECT id, name, sport, description FROM tournaments WHERE user_id = ?", session.get("user_id"))

    for tournament in tournaments:
        tournament["size"] = 8

    tournamentsLength = len(tournaments)

    return render_template("index.html", tournaments=tournaments, tournamentsLength=tournamentsLength)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", alert=True, alertMsg = "Please provide a username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", alert=True, alertMsg = "Please provide a password")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("login.html", alert=True, alertMsg = "Invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html", invalidUserOrPass=False, provideUser=False, providePassword=False)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        passwordConfirmation = request.form.get("confirmation")

        if not username:
            return render_template("register.html", alert=True, alertMsg="Please provide a username")
        if not password:
            return render_template("register.html", alert=True, alertMsg="Please provide a password")
        if not passwordConfirmation:
            return render_template("register.html", alert=True, alertMsg="Please confirm your password")

        sameUsernameCount = db.execute("SELECT COUNT(*) FROM users WHERE username = ?", username)
        if sameUsernameCount[0]["COUNT(*)"] != 0:
            return render_template("register.html", alert=True, alertMsg="User already exists")

        if password != passwordConfirmation:
            return render_template("register.html", alert=True, alertMsg="Passwords don't match")

        hash = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        return render_template("create.html")
    if request.method == "POST":
        if not request.form.get("name"):
            return render_template("create.html", alert=True, alertMsg="Please provide a name")
        elif len(request.form.get("name")) > 15:
            return render_template("create.html", alert=True, alertMsg="Name is too long")
        elif len(request.form.get("description")) > 50:
            return render_template("create.html", alert=True, alertMsg="Description is too long")
        elif len(request.form.get("sport")) > 10:
            return render_template("create.html", alert=True, alertMsg="Sport Name is too long")

        for i in range(1, 9):
            if not request.form.get(f"team{i}"):
                return render_template("create.html", alert=True, alertMsg="Please provide every team")
            elif len(request.form.get(f"team{i}")) > 10:
                return render_template("create.html", alert=True, alertMsg=f"Team {i} name is too long")

        name = request.form.get("name")
        description = request.form.get("description")
        sport = request.form.get("sport")

        tournamentID = db.execute("INSERT INTO tournaments(name, description, user_id, sport) VALUES (?, ?, ?, ?)", name, description,session.get("user_id"), sport)

        teams = []

        for i in range(1, 9):
            teams.append(request.form.get(f"team{i}"))

        shuffle(teams)

        for i in range(8):
            db.execute("INSERT INTO teams(name, seed, tournament_id) VALUES (?, ?, ?)", teams[i], i, tournamentID)

        for i in range(0, 8, 2):
            localTeam = teams[i]
            visitTeam = teams[i + 1]
            localID = db.execute("SELECT id FROM teams WHERE seed = ? AND tournament_id = ?", i, tournamentID)
            visitID = db.execute("SELECT id FROM teams WHERE seed = ? AND tournament_id = ?", i + 1, tournamentID)
            if i == 0:
                seed = 0
            else:
                seed = i / 2
            db.execute("INSERT INTO matches(local_id, visit_id, round, tournament_id, seed) VALUES (?, ?, ?, ?, ?)", localID[0]["id"], visitID[0]["id"], 1, tournamentID, seed)

        # create semifinals

        db.execute("INSERT INTO matches(tournament_id, round, local_prev_match_seed, visit_prev_match_seed, seed) VALUES (?, 2, 0, 1, 4)", tournamentID)
        db.execute("INSERT INTO matches(tournament_id, round, local_prev_match_seed, visit_prev_match_seed, seed) VALUES (?, 2, 2, 3, 5)", tournamentID)

        # create final

        db.execute("INSERT INTO matches(tournament_id, round, local_prev_match_seed, visit_prev_match_seed, seed) VALUES (?, 3, 4, 5, 6)", tournamentID)

        # just to know, quarter-finals 0-3, semifinals 4-5, final 6

    return redirect("/")


@app.route("/tournament", methods=["GET", "POST"])
@login_required
def tournament():
    if request.method == "GET":
        tournament_id = request.args.get("tournament_id")
    else:
        tournament_id = request.form.get("tournament_id")
    tournament = db.execute("SELECT * FROM tournaments WHERE id = ?", tournament_id)

    if session.get("user_id") == tournament[0]["user_id"]:
        teams = db.execute("SELECT * FROM teams WHERE tournament_id = ?", tournament_id)
        round1 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 1", tournament_id) #quarters
        round2 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 2", tournament_id) #semis
        round3 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 3", tournament_id) #final
    else:
        return redirect("/")

    if request.method == "GET":
        return render_template("tournament.html", tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams, tournament_id=tournament_id)
    else:
        roundNum = request.form.get("round")
        round = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = ?", tournament_id, roundNum)

        for match in round:
            if request.form.get("localPointsIn" + str(match["seed"])) and request.form.get("visitPointsIn" + str(match["seed"])):
                local_points = request.form.get("localPointsIn" + str(match["seed"]))
                visit_points = request.form.get("visitPointsIn" + str(match["seed"]))
                if (int(local_points) > 99 and int(local_points) < 0) or (int(visit_points) > 99 and int(visit_points) < 0):
                    return render_template("tournament.html", tournament_id=tournament_id, tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams, alert=True, alertMsg="Score has to be a positive 2 digit number")
            else:
                return render_template("tournament.html", tournament_id=tournament_id, tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams, alert=True, alertMsg="Please input every result")

        for match in round:
            local_points = request.form.get("localPointsIn" + str(match["seed"]))
            visit_points = request.form.get("visitPointsIn" + str(match["seed"]))
            if local_points > visit_points:
                winner_id = db.execute("SELECT local_id FROM matches WHERE id = ?", match["id"])
                db.execute("UPDATE matches SET local_points = ?, visit_points = ?, winner_id = ? WHERE id = ?", local_points, visit_points, winner_id[0]["local_id"], match["id"])

                if match["seed"] % 2 == 0:
                    db.execute("UPDATE matches SET local_id = ? WHERE local_prev_match_seed = ? AND tournament_id = ?", winner_id[0]["local_id"], match["seed"], tournament_id)
                else:
                    db.execute("UPDATE matches SET visit_id = ? WHERE visit_prev_match_seed = ? AND tournament_id = ?", winner_id[0]["local_id"], match["seed"], tournament_id)
            elif visit_points > local_points:
                winner_id = db.execute("SELECT visit_id FROM matches WHERE id = ?", match["id"])
                db.execute("UPDATE matches SET local_points = ?, visit_points = ?, winner_id = ? WHERE id = ?", local_points, visit_points, winner_id[0]["visit_id"], match["id"])

                if match["seed"] % 2 == 0:
                    db.execute("UPDATE matches SET local_id = ? WHERE local_prev_match_seed = ? AND tournament_id = ?", winner_id[0]["visit_id"], match["seed"], tournament_id)
                else:
                    db.execute("UPDATE matches SET visit_id = ? WHERE visit_prev_match_seed = ? AND tournament_id = ?", winner_id[0]["visit_id"], match["seed"], tournament_id)
            else:
                return render_template("tournament.html", tournament_id=tournament_id, tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams, alert=True, alertMsg="Matches cannot end in a draw")

        round1 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 1", tournament_id) #quarters
        round2 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 2", tournament_id) #semis
        round3 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 3", tournament_id) #final
        return render_template("tournament.html", tournament_id=tournament_id, tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams)

