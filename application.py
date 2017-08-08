#!/usr/bin/python
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask import session as login_session
from flask import make_response

# import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Books, User, Base

# auth modules
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials

import random, string, httplib2, json, requests

# configure application
app = Flask(__name__)
app.secret_key = "alchemy"

# configure google client secret
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to database and create database session
# engine = create_engine('sqlite:///books_catalog.db')
engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create helper functions

# authenticate user
def isUser():
    email = login_session['email']
    return session.query(User).filter_by(email=email).one_or_none()


# authenticate admin
def isAdmin():
    return session.query(User).filter_by(email="satvik.sachdeva@gmail.com").one_or_none()


# create new user
def createUser(login_session):
    username = login_session['username']
    email = login_session['email']
    picture = login_session['picture']
    provider = login_session['provider']
    newUser = User(username=username, email=email, picture=picture, provider=provider)
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# create new state
def new_state():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return state


# Set up routes

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = new_state()
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Google sign in
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials  is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Facebook Sign in
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s' \
          '&fb_exchange_token=%s' % (
              app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Show all books
@app.route('/')
@app.route('/books/')
def index():
    state = new_state()
    books = session.query(Books).all()  # get all books
    if 'username' not in login_session:
        return render_template('publicindex.html', books=books)
    else:
        return render_template('index.html', books=books)  # for logged in user


# add new book
@app.route('/books/new/', methods=['GET', 'POST'])
def newBook():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newBook = Books(
            name=request.form['name'],
            author=request.form['author'],
            category=request.form['category'],
            price=request.form['price'],
            description=request.form['description'],
            cover=request.form['cover'],
            user_id=login_session['user_id'])
        session.add(newBook)
        flash('New Book %s Successfully Created' % newBook.name)
        session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('newBook.html')

# edit book
@app.route('/books/category/<string:category>/<int:bookId>/edit/', methods=['POST', 'GET'])
def editBook(category, bookId):
    editedBook = session.query(Books).filter_by(id=bookId, category=category).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedBook.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this book. Please create your own book in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedBook.name = request.form['name']
        flash('Book Successfully Edited %s' % editedBook.name)
        return redirect(url_for('index'))
    else:
        return render_template('editBook.html', book=editedBook, category=category)


# delete book
@app.route('/books/category/<string:category>/<int:bookId>/delete/', methods=['GET', 'POST'])
def deleteBook(category, bookId):
    bookToDelete = session.query(Books).filter_by(id=bookId).one()
    if 'username' not in login_session:
        return redirect('/login')
    if bookToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this book. Please create your " \
               "own book in order to delete.');}</script><body onload='myFunction()''> "
    if request.method == 'POST':
        session.delete(bookToDelete)
        flash('%s Successfully Deleted' % bookToDelete.name)
        session.commit()
        return redirect(url_for('index', id=bookId, category=category))
    else:
        return render_template('deleteBook.html', book=bookToDelete)


# Explore categories
@app.route('/books/category/<string:category>/')
def showCategory(category):
    books = session.query(Books).filter_by(category=category).all()
    state = new_state()
    return render_template('index.html', books=books, category=category, error="No books found. Please try later.",
                           state=state, login_session=login_session)


# show book information
@app.route('/books/category/<string:category>/<int:bookId>/')
def showBooks(category, bookId):
    book = session.query(Books).filter_by(id=bookId, category=category).first()
    state = new_state()
    if book:
        return render_template('bookInfo.html', book=book, currentPage='bookInfo', state=state,
                               login_session=login_session)
    else:
        return render_template('index.html', currentPage='index', error=""" No book found. Please try again later """,
                               state=state, login_session=login_session)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            # del login_session['gplus_id']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        try:
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
        except Exception as e:
            print e
            pass
        flash("You have successfully been logged out.")
        return redirect(url_for('index'))
    else:
        flash("You were not logged in")
        return redirect(url_for('index'))


# JSON Endpoints APIs to view Book Information

@app.route('/books.json/')
def booksJSON():
    books = session.query(Books).all()
    return jsonify(Books=[book.serialize for book in books])


@app.route('/books/category/<string:category>.json/')
def bookCategoryJSON(category):
    books = session.query(Books).filter_by(category=category).all()
    return jsonify(Books=[book.serialize for book in books])


@app.route('/books/category/<string:category>/<int:bookId>.json/')
def bookJSON(category, bookId):
    book = session.query(Books).filter_by(category=category, id=bookId).first()
    return jsonify(Book=book.serialize)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=7000)
