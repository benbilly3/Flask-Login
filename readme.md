# Flask Member System

## Goals
1. Flask member Login
1. OAuth Module:Google、FB、weibo(微博)
2. Admin Module

## Module
See requirements.txt
### **Focus on Flask Dance:**
Doing the OAuth dance with style using Flask, requests, and oauthlib.

## Code Architecture
1. app.py:Flask view&url
2. myproject/__init__.py:DB setting
3. Config.py:OAuth appID

## Member Login Features
1. Confirm Email、Name are not used.
1. Allows flask-login to load the current user and grab their id.
2. Check and hash password.

## Normal Member Customer System

### Use flask_login Module
1. register
1. login
1. logout


## Google Login API

### Setting Detail at:

https://github.com/singingwolfboy/flask-dance-google

To:https://console.developers.google.com/

### apply OAuth

![](https://i.imgur.com/GAF7Nj2.png)



這是您的用戶端 ID:
750796013081-i2sr7euqejkpk5e5bcppnbol6g1dpus3.apps.googleusercontent.com

您的用戶端密鑰如下:
TeCTIoCgSQWOx_iVsQZjV8pq

### Set internet

![](https://i.imgur.com/zs0Fuwr.png)

### Google can't use ngrok.

![](https://i.imgur.com/aKy7JMn.png)


# Flask-Dance Google

Google:https://flask-dance.readthedocs.io/en/v0.7.0/quickstarts/google.html

1. Use make_google_blueprint to enter google OAuth.
1. Use relay website to get gmail,and check if the gmail existed in db.If it was not existed,using gmail to register and set passward is 123456. 
1. Log in the user

```
########Google_Login########

google_Oauth = make_google_blueprint(
    client_id=google_client_id,
    client_secret=google_client_secret,
    # reprompt_consent=True,
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
        user = User(email=email,
                    username=email,
                    password='123456')

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
```
## FB Login API
Enter FB.develope Web to apply app.The appid is important.

https://developers.facebook.com/

Use Ngrok url to test Oauth,because FB requests only "https" can be authorizated.

## FB JS_SDK 
https://github.com/singingwolfboy/flask-dance-facebook

The module has some problems to get Authorization connection.
Change setting methods to use FB SDK in HTML.

code result:

https://dotblogs.com.tw/shadow/2019/10/12/114017

Use Ajax to post User Data to backend.

## Weibo
https://github.com/michaelliao/sinaweibopy/wiki/OAuth2-HOWTO
## Log-out
Clean Every OAuth Token

FB_logout set in JS.
```
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
    return redirect(url_for('home'))
```

