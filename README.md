# CS50 Tournament Maker
#### Video Demo:  https://www.youtube.com/watch?v=W5zl9QRz3ZI
### Description:

This project is a flask web app where you can create tournaments so when you are playing a sport or a game where you need a tournament to organize each match you can make it here.

## How to use it:

First, you have to create an account and register, like anywhere else

![Log In page](readmeFiles/image-2.png)
![Register page](readmeFiles/image-3.png)

Once logged in, you will be redirected to the tournaments page. Here, you will probably have no tournaments, because you just registered, so something like this will appear:

![Tournaments page with no tournaments screenshot](readmeFiles/image.png)

So now you will create a tournament by clicking on that blue link that says **create one!** or clicking on **create** on the navbar.

![Navbar, highliting create button](readmeFiles/image-1.png)

Here, you have to plug in all the info that your tournament needs, the name, the sport, the description and every team, recall that **sport** and **description** are both optional

![Create Page](readmeFiles/image-4.png)

Once you created your tournament, it should redirect you to the tournaments tab, it should look something like this

![Tournaments Tab](readmeFiles/image-5.png)

Here, you just have to click on the tournament name, highlited in blue, so you can start putting some results.

Once entered the tournament page, you should see every match, so you can start plugging in some results, recall that none of the matches can end in a draw, because everything is an elimination round.
When you ended putting every match result in the round, you should click **submit results** button so the next round is updated based on this round results.

![First Round Results](readmeFiles/image-6.png)

Now repeat the process until there is no rounds left, so the winner should appear up in the page, something like this

![Winner](readmeFiles/image-7.png)

And that's It, with this you can create all the tournaments you want when you are playing something with your friends or family, hope you liked it!

## How does it work

### Folders

The app has 2 folders and the files in the main folder

#### "static" folder:

This folder contains the icon of the page that appears in the navbar and the *styles.css* file that contains some custom styling apart from bootstrap that has been used in the project.

#### "templates" folder:

This folder contains every html file that gives life to the project
- **create.html**, the page where you create the tournaments
- **index.html**, the page that displays every tournament you have made
- **layout.html**, the layout of the page, contains the navbar, the footer and the bootstrap links
- **login.html**, the page where you log in
- **register.html**, the page where you register
- **tournament.html**, the page where you see and update the results of your tournaments

#### main folder "project"

This folder is the main one of the app, apart from the previous folders mentioned, it has *tournaments.db*, where all the data is stored, and *app.py*, the file that gives functionality to all the files previously mentioned

#### tournaments.db

This database has 4 tables:
- **users**, that contain each user data

```
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
username TEXT NOT NULL,
hash TEXT NOT NULL);
```

- **tournaments**, contains each tournament data, like the size or the user that owns it

```
CREATE TABLE tournaments(
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
name TEXT NOT NULL,
description TEXT,
user_id INT, sport TEXT NOT NULL,
FOREIGN KEY (user_id) REFERENCES users(id)
);
```

- **teams**, contains every team, linking each of them to the tournaments where they belong

```
CREATE TABLE teams(
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
name TEXT NOT NULL,
tournament_id INTEGER,
FOREIGN KEY (tournament_id) REFERENCES tournaments(id)
);

```

- **matches**, contains every team, linking them to the tournament they belong and the teams that play this match, the winner, the points, round, etc.

```
CREATE TABLE matches(
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
tournament_id INTEGER,
local_id INTEGER,
visit_id INTEGER,
round INTEGER,
local_points INTEGER,
visit_points INTEGER,
winner_id INTEGER,
local_prev_match_seed INTEGER,
visit_prev_match_seed INTEGER,
seed INTEGER,
FOREIGN KEY (tournament_id) REFERENCES tournaments(id),
FOREIGN KEY (local_id) REFERENCES teams(id),
FOREIGN KEY (visit_id) REFERENCES teams(id),
FOREIGN KEY (winner_id) REFERENCES teams(id)
);
```

### app.py

This python file contains a function for each route in the web app, as well as session handling and flask configurations

#### flask configuration

At first, we can see all the flask configuration as well as the database link, and the *login required* to make some routes the neeed of logging in.

```
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Library to use SQLite database
db = SQL("sqlite:///tournaments.db")

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function
```

#### /index
Then you have each route, starting from the index, it takes every tournament from the user logged in to send it to the *index.html*

```
@app.route("/")
@login_required
def index():
    tournaments = db.execute("SELECT id, name, sport, description FROM tournaments WHERE user_id = ?", session.get("user_id"))

    for tournament in tournaments:
        tournament["size"] = 8

    tournamentsLength = len(tournaments)

    return render_template("index.html", tournaments=tournaments, tournamentsLength=tournamentsLength)
```

#### /login

Then, there's the login route (*/login*)

If this route is requested via *GET* it just displays the log in form in *login.html*

```
# User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html", invalidUserOrPass=False, provideUser=False, providePassword=False)
```

If this route is requested via *POST*, at first checks if the form was filled the right way, checking if the user provided a username and a password, if not, it reprompts the user with the log in form.

```
if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", alert=True, alertMsg = "Please provide a username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", alert=True, alertMsg = "Please provide a password")
```

Then, it checks if a user with that username exists and the password is correct, if so it creates the session and logs in the user, if not, it renders the log in page again


```
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
```

#### /logout

Then, there´s the log out route (*/logout), it just clears the session

```
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
```

#### /register


To log in, you have to have an account first, so there is the register route (*/register*)

If the route is requested via *GET*, it just displays *register.html* with the registration form

```
else:
        return render_template("register.html")
```

Else, if the route is requested via *POST* it gets the username, password and it's confirmation from the form, and checks if the form was correctly filled

```
if not username:
            return render_template("register.html", alert=True, alertMsg="Please provide a username")
        if not password:
            return render_template("register.html", alert=True, alertMsg="Please provide a password")
        if not passwordConfirmation:
            return render_template("register.html", alert=True, alertMsg="Please confirm your password")
```

If the form was filled succesfully, it checks if the username already exists in the database, and if passwords match

```
sameUsernameCount = db.execute("SELECT COUNT(*) FROM users WHERE username = ?", username)
        if sameUsernameCount[0]["COUNT(*)"] != 0:
            return render_template("register.html", alert=True, alertMsg="User already exists")

        if password != passwordConfirmation:
            return render_template("register.html", alert=True, alertMsg="Passwords don't match")
```

If everything's done correctly, it creates the account with it's password hash and redirects the user to the log in page

```
hash = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        return redirect("/")
```

#### /create


Then, there's the create route (*/create*)

If the route was requested via *GET*, it renders *create.html* template

So, if the route was requested via *POST*, it checks the form was succesfully filled, by checking if the name exists, every team exists and the sport, description, name and every team name length is correct, even dough it is limited in the create template, html can be edited by the user in the explorer devtools.

```
if not request.form.get("name"):
            return render_template("create.html", alert=True, alertMsg="Please provide a name")
        elif len(request.form.get("name")) > 15:
            return render_template("create.html", alert=True, alertMsg="Name is too long")
        # same with other variables
```

If everything went correct, it starts by creating the tournament with its data

```
name = request.form.get("name")
        description = request.form.get("description")
        sport = request.form.get("sport")

        tournamentID = db.execute("INSERT INTO tournaments(name, description, user_id, sport) VALUES (?, ?, ?, ?)", name, description,session.get("user_id"), sport)
```

Then, it creates the teams and save them in the database, in a random order
```
teams = []

        for i in range(1, 9):
            teams.append(request.form.get(f"team{i}"))

        shuffle(teams)

        for i in range(8):
            db.execute("INSERT INTO teams(name, seed, tournament_id) VALUES (?, ?, ?)", teams[i], i, tournamentID)
```

Then it creates every match, by getting every team id from the tournament and plugging them into the matches

The seed is to detect later which was the previous match of a team in the incoming rounds

```
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
```

#### /tournament


The last function is for the tournaments route (*/tournament*)

At first, the function looks up the tournament by it's ID, requested via *GET* or *POST*

```
if request.method == "GET":
        tournament_id = request.args.get("tournament_id")
    else:
        tournament_id = request.form.get("tournament_id")
    tournament = db.execute("SELECT * FROM tournaments WHERE id = ?", tournament_id)
```

Then it checks if the tournament owner is the user trying to access it, if so, it creates a variable for each round and an array for the teams

```
if session.get("user_id") == tournament[0]["user_id"]:
        teams = db.execute("SELECT * FROM teams WHERE tournament_id = ?", tournament_id)
        round1 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 1", tournament_id) #quarters
        round2 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 2", tournament_id) #semis
        round3 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 3", tournament_id) #final
    else:
        return redirect("/")
```

If everything's done succesfully, it again checks if the route was requested via *POST* or *GET*, if it was requested via *GET* it renders the tournament page, passing in each match and team.

If it was requested via *POST*, it checks wich round was submitted.

```
    roundNum = request.form.get("round")
    round = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = ?", tournament_id, roundNum)
```

Then, it looks for each match in the round, if it was correctly submitted via form, checking if every result were plugged in, and the results aren´t too big

```
for match in round:
        if request.form.get("localPointsIn" + str(match["seed"])) and request.form.get("visitPointsIn" + str(match["seed"])):
            local_points = request.form.get("localPointsIn" + str(match["seed"]))
            visit_points = request.form.get("visitPointsIn" + str(match["seed"]))
            if (int(local_points) > 99 and int(local_points) < 0) or (int(visit_points) > 99 and int(visit_points) < 0):
                return render_template("tournament.html", tournament_id=tournament_id, tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams, alert=True, alertMsg="Score has to be a positive 2 digit number")
```

If everything was succesfully submitted, it starts updating the results, starting by checking the winner and updating the database, then, it updates the next round matches based on the match currently being updated

```
if local_points > visit_points:
                winner_id = db.execute("SELECT local_id FROM matches WHERE id = ?", match["id"])
                db.execute("UPDATE matches SET local_points = ?, visit_points = ?, winner_id = ? WHERE id = ?", local_points, visit_points, winner_id[0]["local_id"], match["id"])

                if match["seed"] % 2 == 0:
                    db.execute("UPDATE matches SET local_id = ? WHERE local_prev_match_seed = ? AND tournament_id = ?", winner_id[0]["local_id"], match["seed"], tournament_id)
                else:
                    db.execute("UPDATE matches SET visit_id = ? WHERE visit_prev_match_seed = ? AND tournament_id = ?", winner_id[0]["local_id"], match["seed"], tournament_id)
```

It's the same if *visit_points* is greater than *local_points* but updating everything based on the victory of the visitor

Once everything was updated in the database, it now updates the local variables of each round with the new data (looked up in the database) and renders the tournament page again with each update

```
round1 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 1", tournament_id) #quarters
        round2 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 2", tournament_id) #semis
        round3 = db.execute("SELECT * FROM matches WHERE tournament_id = ? AND round = 3", tournament_id) #final
        return render_template("tournament.html", tournament_id=tournament_id, tournament=tournament, round1=round1, round2=round2, round3=round3, teams=teams)
```

### templates

This project has six templates, let's see each of them

#### layout.html

This template, as the name says, it's the layout of the app, it contains the navbar, the footer, and the alerts

The navbar is a bootstrap element, with the icon of the page, if the user is logged in, it has 2 avaible buttons and one disabled. The buttons are the tournaments tab */index*, and the create tournament page */create*, the third button, which is disabled, is the explore button, which it's meant to work in the future. It also has the log out button */logout*, to log the user out

If the user is not logged in, the buttons avaible are "log in" */login* and "register" */register*

```
    <nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom">
            <div class="container-fluid">
              <a class="navbar-brand" href="/"><img src="/static/icon.png" alt="Icon" class="rounded-circle"></a>
              <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
              </button>
              <div class="collapse navbar-collapse" id="navbarNav">
                {% if session["user_id"] %}
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Tournaments</a></li>
                    <li class="nav-item"><a class="nav-link" href="/create">Create</a></li>
                    <li class="nav-item"><a class="nav-link disabled" href="#">Explore</a></li>
                </ul>
                <ul class="navbar-nav ms-auto">
                  <li class="nav-item"><a class="nav-link" href="/logout">Log Out</a></li>
                </ul>
                {% else %}
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="/register">Register</a></li>
                    <li class="nav-item"><a class="nav-link" href="/login">Log In</a></li>
                </ul>
                {% endif %}
              </div>
            </div>
          </nav>
```

The footer it's just a *p* tag that says *"CS50 Tournament Maker, CS50x Final Project by NESVEX"*

Then there's the alerts, this is composed by 2 jinja variables and a *div* tag.

The first variable *alert* it's meant to be a boolean that when it's true it displays the alert div, then there's *alertMsg* that is meant to be a string that represents the alert.


```
{% if alert %}
        <div class="alert alert-danger" role="alert">
            {{alertMsg}}
        </div>
{% endif %}
```

Those variables are toggled when rendering any template and setting *alert* to true and *alertMsg* to any value, for example:

```
return render_template("login.html", alert=True, alertMsg = "Invalid username and/or password")
```

#### login.html & register.html

these two are just a form that represents the log in/register form , asking the user for it's username and password

```
<form action="/login" method="post">
    <div class="mb-3">
        <input autocomplete="off" autofocus class="form-control mx-auto w-auto" name="username" placeholder="Username" type="text">
    </div>
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" name="password" placeholder="Password" type="password">
    </div>
    <button class="btn btn-outline-dark" type="submit">Log In</button>
</form>
```

for *register.html* there's one more input which represent the password confirmation

```
<div class="mb-3">
    <input class="form-control mx-auto w-auto" name="confirmation" placeholder="Confirm your password" type="password">
</div>
```

#### index.html

*index.html* takes every tournament from the user logged in and makes a table with it's info, if the user has no tournaments yet it displays a text that says

```
<thead>
        <tr class="table-active">
            <th scope="col">Name</th>
            <th scope="col">Size</th>
            <th scope="col">Sport</th>
            <th scope="col" class="description">Description</th>
        </tr>
</thead>
```
Then there's the table below with each tournament

At the bottom, there's a javascript script that detect the device with, so if it's below 600px the description of each tournament does not show up.

```
<script>
    window.addEventListener('resize', function() {
      var descriptions = document.querySelectorAll('.description');
      if (window.innerWidth <= 600) {
        descriptions.forEach(function(description) {
          description.hidden = true;
        });
      } else {
        descriptions.forEach(function(description) {
          description.hidden = false;
        });
      }
    });

    // Set initial state
    if (window.innerWidth <= 600) {
      var descriptions = document.querySelectorAll('.description');
      descriptions.forEach(function(description) {
        description.hidden = true;
      });
    }
</script>
```

#### create.html

This template is just a big form asking for all the data that your tournament needs, it asks for the name, sport (optional), description (optional), and every team name

Each input has a *maxlength* attribute that determines the maximum length of the info required, 15 for the name, 10 for sport and each team, and 50 for the description

#### tournament.html

The first thing this template does is to check if the tournament requested has ended, if so, it displays the winner at the top

```
{% if round3[0]["winner_id"] != NULL %}
    {% for team in teams %}
        {% if team["id"] == round3[0]["winner_id"] %}
            <h2>The winner is: {{ team["name"] }}!</h5>
        {% endif %}
    {% endfor %}
{% endif %}
```

Then it displays each round, checking if the results had already been submitted, if so, it disables the inputs for each result and displays the result

```
<form action="/tournament" method="post">
            <table class="table table-bordered round align-middle mx-auto">
                <tbody>
                    {% for match in round1 %}
                        <tr>
                            {% for team in teams %}
                                {% if team["id"] == match["local_id"] %}
                                    <td class="match-team">{{ team["name"] }}</td>
                                {% endif %}
                            {% endfor %}

                            {% if match['local_points'] != None and match['visit_points'] != None %}
                                <td ><input type="number" class="form-control number-input" name="localPointsIn{{ match['seed'] }}" disabled value="{{match['local_points']}}"></td>
                                <td ><input type="number" class="form-control number-input" name="visitPointsIn{{ match['seed'] }}" disabled value="{{match['visit_points']}}"></td>
                            {% else %}
                                <td ><input type="number" class="form-control number-input" name="localPointsIn{{ match['seed'] }}" min="0"max="99"></td>
                                <td ><input type="number" class="form-control number-input" name="visitPointsIn{{ match['seed'] }}" min="0"max="99"></td>
                            {%endif%}

                            {% for team in teams %}
                                {% if team["id"] == match["visit_id"] %}
                                    <td class="match-team">{{ team["name"] }}</td>
                                {% endif %}
                            {% endfor %}
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
            <input type="hidden" name="round" value="1">
            <input type="hidden" name="tournament_id" value="{{ tournament_id }}">
            <button class="btn btn-outline-dark submit-tournament" type="submit">Submit Results</button>
        </form>
```
*the table for the first round
