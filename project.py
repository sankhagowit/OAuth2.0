from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

#Anti-Forgery Required Modules
from flask import session as login_session # need to rename as we're using session in SQLAlchemy
# Login session works like a dictionary, enabling us to store values in it for the length of a session
import random, string

# Imports for Gconnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=["POST"])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps("Invalid state parameter."), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Invalid State Parameter"
        return response
    access_token = request.data

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    token = result.split("&")[0]
    userinfo_url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    #Populate Login Session
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # Get user picture... has to be a separate API Call
    url = 'https://graph.facebook.com/v2.8/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result =  h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data['data']['url']

    # see if user exists
    user_id = getUserID(login_session['email'])
    print "call to check user_id found: " + str(user_id)
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


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['facebook_id']
    return "You have been logged out"


CLIENT_ID = json.loads(open('client_secrets.json','r').read())['web']['client_id']
@app.route('/gconnect', methods=["POST"])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid State Parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Invalid State Parameter"
        return response

    code = request.data # proceed, collect one time code from server
    # try to use this one time code to get a token
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage' # specify w/ postmessage this is one time code flow my server will be sending off
        credentials = oauth_flow.step2_exchange(code) # initiate exchange. step2_Exchange exchanges one time code auhtorization code for a credentials object.
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Failed to upgrade the authorization code"
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1]) #verify with google api server that token is valid for use with JSON 'GET' request
    print "result: "
    print result

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        print "error in server fetching data from google api"
        return response

    # Verify that the access token is used for the intended use... by matching user credentials
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Token's user id doesn't match the given user id"
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's"), 401)
        print "Token's Client ID does not match app's"
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if the user is already logged into the system
    stored_credentials = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current User is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        print "Current user already connected"
        return response

    # Assuming none of these if statements are not true... don't they all need return statements then?
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user Information using google+ api.. send request to google server
    # using the access token that we got from google.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    print data

    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    print login_session

    # See if user exsits, if it doesn't, make a new one
    user_id = getUserID(login_session['email'])
    print "call to check user_id found: " + str(user_id)
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


# Disconnect Code
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('access_token')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Current user not connected"
        return response

    # Execute HTTP GET request to revoke current token.
    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0] # googles response

    if result['status'] == '200':
        # Reset the user's session.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps("Successfully disconnected"), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # For whatever reason, the given token was invalid, something went wrong in the disconnect process
        response = make_response(json.dumps("Failed to revoke token for given user"), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    if 'username' not in login_session:
        return redirect('/login')
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    if 'username' not in login_session:
        return render_template('publicrestaurants.html', restaurants=restaurants)
    return render_template('restaurants.html', restaurants = restaurants)


#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(name = request.form['name'], user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if editedRestaurant.user_id == login_session['user_id']:
        if request.method == 'POST':
            if request.form['name']:
                editedRestaurant.name = request.form['name']
                flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
                return redirect(url_for('showRestaurants'))
        else:
            return render_template('editRestaurant.html', restaurant=editedRestaurant)
    else:
        return redirect(url_for('showRestaurants'))


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] == restaurantToDelete.user_id:
        if request.method == 'POST':
            session.delete(restaurantToDelete)
            flash('%s Successfully Deleted' % restaurantToDelete.name)
            session.commit()
            return redirect(url_for('showRestaurants'))
        else:
            return render_template('deleteRestaurant.html', restaurant=restaurantToDelete)
    else:
        return redirect(url_for('showRestaurants'))

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    print creator.id, creator.name
    if 'username' in login_session:
        if restaurant.user_id == login_session['user_id']:
            return render_template('menu.html', items=items, restaurant=restaurant)
    return render_template('publicmenu.html', items=items, restaurant=restaurant, creator=creator)



#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id, user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    if editedItem.user_id == login_session['user_id']:
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            if request.form['price']:
                editedItem.price = request.form['price']
            if request.form['course']:
                editedItem.course = request.form['course']
            session.add(editedItem)
            session.commit()
            flash('Menu Item Successfully Edited')
            return redirect(url_for('showMenu', restaurant_id = restaurant_id))
        else:
            return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)
    else:
        redirect(url_for('showMenu', restaurant_id=restaurant_id))


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
    if itemToDelete.user_id == login_session['user_id']:
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            flash('Menu Item Successfully Deleted')
            return redirect(url_for('showMenu', restaurant_id = restaurant_id))
        else:
            return render_template('deleteMenuItem.html', item = itemToDelete)
    else:
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
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


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
