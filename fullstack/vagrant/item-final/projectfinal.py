from flask import Flask, render_template, flash, url_for, \
                redirect, request, jsonify, \
                session as login_session, make_response

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Region, Trail, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from functools import wraps

import random
import string
import httplib2
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

CREATOR_ERROR = '''This is a public page. If you are the
                creator of this trail and would like to make changes,
                please sign in to access the admin view. '''


def getSession():
    """Return a database session."""
    engine = create_engine('sqlite:///mtbtrailswithusers.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    return session


def checkAuth():
    """Check if user is logged in and return True or False."""
    auth = ''
    if 'username' in login_session:
        auth = True
    else:
        auth = False
    return auth


def checkCreator(region):
    """Return True or False to see if user created the region."""
    creator = ''
    if login_session.get('user_id') == region.user_id:
        creator = True
    else:
        creator = False
    return creator


# USER HELPER FUNCTIONS
def getUserID(email):
    """Return user_id for db. Accept user email as argument."""
    session = getSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.user_id
    except:
        return None


def getUserInfo(user_id):
    """Take the user_id from the db, return the user object."""
    session = getSession()
    user = session.query(User).filter_by(user_id=user_id).one()
    return user


def createUser(login_session):
    """Create a new user in db, and return
       the user's user_id from the db."""
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session = getSession()
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.user_id


def updatePicture(login_session):
    """Check to make sure picture is up to date."""
    session = getSession()
    user = session.query(User).filter_by(email=login_session['email']).one()
    user.picture = login_session['picture']
    session.add(user)
    session.commit()
    return user.user_id


# DECORATOR FUNCTIONS
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if checkAuth():
            return f(*args, **kwargs)
        else:
            return redirect(url_for('showLogin'))
    return decorated_function


def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        region_id = kwargs.get('region_id')
        session = getSession()
        region = session.query(Region) \
                .filter_by(region_id=region_id).one()
        kwargs['region'] = region
        kwargs['session'] = session
        if checkCreator(region):
            return f(*args, **kwargs)
        else:
            flash(CREATOR_ERROR)
            session.close()
            return redirect(url_for('showPublicTrail', region_id=region_id))
    return decorated_function


def prepare_trail(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        region_id = kwargs.get('region_id')
        session = getSession()
        session = getSession()
        region = session.query(Region) \
                .filter_by(region_id=region_id).one()
        trails = session.query(Trail) \
                .filter_by(region_id=region_id).all()
        kwargs['region'] = region
        kwargs['trails'] = trails
        kwargs['description'] = []
        kwargs['difficulty'] = []
        kwargs['city'] = []

        return f(*args, **kwargs)

    return decorated_function


@app.route('/login/')
def showLogin():
    """Pass a state token for login."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', state=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Google plus sign in."""
    # validate state token
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
    if result.get('user_id') != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID doesn't match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # see if user exists, if not then make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    # updatePicture(login_session)
    login_session['user_id'] = user_id

    flash("you are now logged in as %s" % login_session['username'])
    output = "done!"
    return output


@app.route('/gdisconnect/')
def gdisconnect():
    """Google plus sign-out."""
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token
    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    response = requests.get(url).json()

    if result['status'] != '200':
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST', 'GET'])
def fbconnect():
    """Facebook sign-in."""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data
    # exchange client token for long-lived server-side token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']  # noqa
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']  # noqa
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # use token to get user info from API
    userinfo_url = 'https://graph.facebook.com/v2.2/me'
    # strip expire tag from access token
    token = result.split('&')[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']
    # get user picture
    url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data['data']['url']
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    # updatePicture(login_session)
    login_session['user_id'] = user_id

    flash("you are now logged in as %s" % login_session['username'])
    output = "done!"
    return output


@app.route('/fbdisconnect/')
def fbdisconnect():
    """Facebook sign-out."""
    facebook_id = login_session['facebook_id']
    access_token = login_session.get('access_token')
    url = 'https://graph.facebook.com/%s/premissions?access_token=%s' % (facebook_id, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, "DELETE")[1]
    return "you have been logged out"


@app.route('/disconnect/')
def disconnect():
    """Will sign-out user if their signed in through facebook or google."""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        # delete everything else in the login session
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have been successsfully logged out.")

        return redirect(url_for('showRegions'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRegions'))


@app.route('/')
@app.route('/mtbtrails/')
def showRegions():
    """Show all the regions we have stored in the db."""
    session = getSession()
    regions = session.query(Region).all()
    if regions == []:
        flash('You currently have no regions to list')

    session.close()
    return render_template('regions.html', regions=regions)


@app.route('/mtbtrails/new/', methods=['GET', 'POST'])
@login_required
def newRegion():
    """Create a new region."""
    if request.method == 'POST':
        newName = request.form['name']
        if not newName:
            error = 'Please enter in a new restaurant name'
            return render_template('newRegion.html', error=error)
        else:
            session = getSession()
            newRegion = Region(name=newName,
                               user_id=login_session['user_id'])
            session.add(newRegion)
            session.commit()
            flash("New region created!")

            session.close()
            return redirect(url_for('showRegions'))
    else:
        return render_template('newRegion.html')


@app.route('/mtbtrails/<int:region_id>/edit/', methods=['GET', 'POST'])
@login_required
@owner_required
def editRegion(region_id, region, session):
    """Edit an existing region."""
    if request.method == 'POST':
        editedName = request.form['name']
        if not editedName:
            error = 'Please enter in a new region name'
            session.close()
            return render_template('editRegion.html',
                                   region_id=region_id,
                                   region=region,
                                   error=error)
        else:
            region.name = editedName
            session.add(region)
            session.commit()
            flash("Region renamed")

            session.close()
            return redirect(url_for('showTrail', region_id=region_id))
    else:
        session.close()
        return render_template('editRegion.html',
                               region_id=region_id,
                               region=region)


@app.route('/mtbtrails/<int:region_id>/delete/', methods=['GET', 'POST'])
@login_required
@owner_required
def deleteRegion(region_id, region, session):
    """Delete an existing region."""
    if request.method == 'POST':
        session.delete(region)
        session.commit()
        flash("Region deleted")

        session.close()
        return redirect(url_for('showRegions'))
    else:
        session.close()
        return render_template('deleteRegion.html',
                               region_id=region_id,
                               region=region)


@app.route('/mtbtrails/<int:region_id>/public/')
@app.route('/mtbtrails/<int:region_id>/public/trail/')
@prepare_trail
def showPublicTrail(**kwargs):
    kwargs['creator'] = getUserInfo(kwargs['region'].user_id)
    return render_template('publicTrail.html', **kwargs)


@app.route('/mtbtrails/<int:region_id>/')
@app.route('/mtbtrails/<int:region_id>/trail/')
@owner_required
@prepare_trail
def showTrails(**kwargs):
    """Show trail for selected region."""
    if kwargs['trails'] == []:
        flash('You currently have no trails in this trail')

    kwargs['session'].close()
    del kwargs['session']
    return render_template('trail.html', **kwargs)


@app.route('/mtbtrails/<int:region_id>/trail/new/', methods=['GET', 'POST'])
@login_required
@owner_required
def newTrail(region_id, region, session):
    """Create a new trail."""
    if request.method == 'POST':
        name = request.form.get('name')
        city = request.form.get('city')
        description = request.form.get('description')
        difficulty = request.form.get('difficulty')
        if not name or not city or not description or not difficulty:
            error = '''All form fields are required in order to create
                    a new trail'''
            session.close()
            return render_template('newTrail.html',
                                   region_id=region_id,
                                   region=region,
                                   error=error,
                                   name=name,
                                   city=city,
                                   description=description,
                                   difficulty=difficulty)
        else:
            newTrail = Trail(name=name,
                             difficulty=difficulty,
                             description=description,
                             city=city,
                             region_id=region_id)
            session.add(newTrail)
            session.commit()
            flash("New trail created!")

            session.close()
            return redirect(url_for('showTrails', region_id=region_id))
    else:
        session.close()
        return render_template('newTrail.html',
                               region_id=region_id,
                               region=region)


@app.route('/mtbtrails/<int:region_id>/trail/<int:trail_id>/edit/',
           methods=['GET', 'POST'])
@login_required
@owner_required
def editTrail(region_id, trail_id, region, session):
    """Edit an existing trail."""
    itemToBeEdited = session.query(Trail).filter_by(trail_id=trail_id).one()
    if request.method == 'POST':
        name = request.form.get('name')
        city = request.form.get('city')
        description = request.form.get('description')
        difficulty = request.form.get('difficulty')
        if name:
            itemToBeEdited.name = name
        if city:
            itemToBeEdited.city = city
        if description:
            itemToBeEdited.description = description
        if difficulty:
            itemToBeEdited.price = difficulty

        session.add(itemToBeEdited)
        session.commit()
        flash("Trail edited")

        session.close()
        return redirect(url_for('showTrails', region_id=region_id))
    else:
        session.close()
        return render_template('editTrail.html',
                               region_id=region_id,
                               trail_id=trail_id,
                               region=region,
                               item=itemToBeEdited)


@app.route('/mtbtrails/<int:region_id>/menu/<int:trail_id>/delete/',
           methods=['GET', 'POST'])
@login_required
@owner_required
def deleteTrail(region_id, trail_id, region, session):
    """Delete an existing trail."""
    itemToBeDeleted = session.query(Trail).filter_by(trail_id=trail_id).one()
    if request.method == 'POST':
        session.delete(itemToBeDeleted)
        session.commit()
        flash("Trail deleted")

        session.close()
        return redirect(url_for('showTrails', region_id=region_id))
    else:
        session.close()
        return render_template('deleteTrail.html',
                               region_id=region_id,
                               trail_id=trail_id,
                               region=region,
                               item=itemToBeDeleted)


@app.route('/mtbtrails/JSON/')
def regionsJSON():
    """Return a JSON endpoint for all regions."""
    session = getSession()
    regions = session.query(Region).all()

    session.close()
    return jsonify(Region=[region.serialize for region in regions])


@app.route('/mtbtrails/<int:region_id>/trail/JSON/')
def trailJSON(region_id):
    """Return a JSON endpoint for a region's trail page."""
    session = getSession()
    region = session.query(Region) \
             .filter_by(region_id=region_id).one()
    trails = session.query(Trail) \
             .filter_by(region_id=region_id).all()

    session.close()
    return jsonify(Trail=[trail.serialize for trail in trails])


@app.route('/mtbtrails/<int:region_id>/trail/<int:trail_id>/JSON/')
def trailItemJSON(region_id, trail_id):
    """Return a JSON endpoint for an individual trail."""
    session = getSession()
    item = session.query(Trail).filter_by(trail_id=trail_id).one()
    session.delete(item)
    session.commit()

    session.close()
    return jsonify(trailItem=item.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
