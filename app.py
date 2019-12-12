from myproject import app,db
from myproject.models import User
from myproject.forms import LoginForm,RegistrationForm
from config import google_client_id,google_client_secret,fb_client_id,fb_client_secret
from flask import request,flash,Flask, redirect, url_for, render_template
from flask_login import login_user,login_required,logout_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint,facebook
import os
import json
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = '1'
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = '1'


########Normal_Member_Login########
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/welcome')
@login_required
def welcome_user():
    return render_template('welcome_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    #FB login check db
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(
                email=email,
                username=email,
                password='123456'
            )

            db.session.add(user)
            db.session.commit()
            user = User.query.filter_by(email=email).first()
        login_user(user)
        print(email)

    ##normal login##
    form = LoginForm()
    if form.validate_on_submit():
        # Grab the user from our User Models table
        user = User.query.filter_by(email=form.email.data).first()
        if user.check_password(form.password.data) and user is not None:
            # Log in the user
            login_user(user)
            flash('Logged in successfully.')
            next = request.args.get('next')
            if next == None or not next[0] == '/':
                next = url_for('welcome_user')

            return redirect(next)

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering! Now you can login!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

########Google_Login########

google_Oauth = make_google_blueprint(
    client_id=google_client_id,
    client_secret=google_client_secret,
    offline=True,
    scope=["profile", "email"],
    redirect_url='/welcome_google'
)

app.register_blueprint(google_Oauth, url_prefix="/login")
@app.route("/login/google")
def google_login():
    if not google.authorized:
        return render_template(url_for("google.login"))
    return render_template("welcome_google.html",email=email)

@app.route('/welcome_google')
def welcome_google():
    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    email=resp.json()["email"]
    # check gmail in db,if not in db,create user data
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(
            email=email,
            username=email,
            password='123456'
        )

        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(email=email).first()

    # and log in
    login_user(user)

    # If a user was trying to visit a page that requires a login
    # flask saves that URL as 'next'.
    next = request.args.get('next')

    # So let's now check if that next exists, otherwise we'll go to
    # the welcome page.
    if next == None or not next[0] == '/':
        next = url_for('welcome_user')
        return redirect(next)

#####logout#####
@app.route('/logout')
@login_required
def logout():
    #delete google tocken
    try:
        token = google_Oauth.token["access_token"]
        resp = google.post(
            "https://accounts.google.com/o/oauth2/revoke",
            params={"token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert resp.ok, resp.text
        logout_user()  # Delete Flask-Login's session cookie
        del blueprint.token  # Delete OAuth token from storage
    except:
        pass
    logout_user()
    flash('You logged out!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True,host='127.0.0.1', port=8000)


