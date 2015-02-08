from flask import current_app, flash, Flask, jsonify, Markup, redirect, render_template, redirect, request, session, url_for
import os, json, logging, markdown, urllib, urllib2, pymongo
from bson.objectid import ObjectId
from datetime import datetime

app = Flask(__name__)
app.config.update(DEBUG = True, SECRET_KEY = 'X2U&692fW}{mWRE"i+y:42WW3S]eQ,')

settings = {
	"NAME": "nemrut", "REDIRECT_URI": "http://nemrutblog.herokuapp.com/login",
	"CLIENT_ID": "000000004C12E5C0", "CLIENT_SECRET": "MkwlvYWZv26ycAkv3J5uzquCbcsLQL5f", "CLIENT_SCOPE": "wl.skydrive,wl.skydrive_update",
	"AUTH_URL": "https://login.live.com/oauth20_token.srf", "GRANT_TYPE": "authorization_code", 
	"LOGIN_URL_FORMAT": 'https://login.live.com/oauth20_authorize.srf?client_id=%s&scope=%s&response_type=code&redirect_uri=%s', "SDK_URL_FORMAT": "https://apis.live.net/v5.0/%s",
	"MONGODB_URI": "mongodb://crowdy:crowdy@ds045157.mongolab.com:45157/crowdy"
}

logging.basicConfig(level = logging.DEBUG)
logger = logging.getLogger(__name__)

client = pymongo.MongoClient(settings["MONGODB_URI"])
client_db = client.get_default_database()
db = client_db[settings["NAME"]]

@app.route('/')
def index():
	if logged_in():
		return redirect(url_for('home'))
	return render_template("login.html", login_url = settings["LOGIN_URL_FORMAT"] % (settings["CLIENT_ID"], settings["CLIENT_SCOPE"], settings["REDIRECT_URI"]))

@app.route('/login')
def login():
	[succedded, response] = make_request(create_auth_request(request))
	if succedded:
		if is_user_registered(response["user_id"], response["access_token"]):
			return redirect(url_for('home'))
		return redirect(url_for('get_started'))
	return error_page(response["code"], response["message"])
	
@app.route('/logout')
def logout():
	session.clear()
	return redirect(url_for('index'))

@app.route("/get-started", methods=['GET', 'POST'])
def get_started():
	if request.method == 'POST':
		[succedded, message] = register(request.form.get('username', ''), request.form.get('name', ''), request.form.get('agreement', False))
		if succedded:
			return redirect(url_for('home'))
		else:
			flash(message)
	
	return render_template("getstarted.html", title = "Getting Started", subtitle = "It looks like this is your first time. Let's get some details about you...")
	
@app.route('/home')
def home():
	if not(logged_in()):
		return redirect(url_for('index'))
	
	[succedded, response] = make_request(settings["SDK_URL_FORMAT"] % ('me/skydrive/files?access_token=%s' % session['access_token']))
	if succedded:
		[folder_found, file_id, error_msg] = find_app_folder(response)
		if not(folder_found):
			create_app_folder(session['access_token'])
			files = []
		else:
			files = read_app_folder(file_id, session['access_token'])
			db.update({ '_id': ObjectId(session['_id']) },  { '$set': { 'files': files } })
		return render_template("home.html", subtitle = session['username'], title = session['name'], user_id = session['user_id'], response = error_msg, files = files)
	return error_page(response["code"], response["message"])

@app.route("/user/<username>")
def blog(username):
	users = db.find({ 'username': username })
	if users.count() > 0:
		user = users[0]
		return render_template("user.html", title = user['name'], subtitle = user['username'], username = username, files = user['files'])
	
	return error_page(404, "User cannot be found")
	
@app.route("/post/<username>/<title>")
def read(username, title):
	users = db.find({ 'username': username })
	if users.count() > 0:
		user = users[0]
		for file in user['files']:
			if file['name'] == title:
				return render_template("post.html", content = Markup(markdown.markdown(file['content'])), title = file['name'], time = file['updated_time'], username = user['username'], subtitle = user['name'])
	
	return error_page(404, "Content cannot be found")

### ### ### ### ### Live SDK related methods ### ### ### ### ###
def create_auth_request(request):
	logger.info('Auth is requested')

	code = request.args.get('code', '')
	values = {'client_id': settings["CLIENT_ID"], 'redirect_uri': settings["REDIRECT_URI"], 'client_secret': settings["CLIENT_SECRET"], 'code': code, 'grant_type': settings["GRANT_TYPE"]}
	data = urllib.urlencode(values)
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}
	return urllib2.Request(settings["AUTH_URL"], data, headers)

def find_app_folder(data):
	found = False
	error_msg = ""
	file_id = ""
	
	if not("data" in data):
		error_msg = "The response is malformed."
		return [found, error_msg]
	
	files = data["data"]
	for file in files:
		if "type" in file and file["type"] == "folder" and file["name"] == settings["NAME"]:
			file_id = file["id"]
			found = True
			break
	
	if not(found):
		error_msg = "Folder cannot be found."
	return [found, file_id, error_msg]

def create_app_folder(access_token):
	data = json.dumps({'name': settings["NAME"]})
	headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
	post_request = urllib2.Request(settings["SDK_URL_FORMAT"] % 'me/skydrive', data, headers)
	
	[succedded, response] = make_request(post_request)
	if succedded:
		return redirect(url_for('home'))
	return error_page(response["code"], response["message"])

def read_app_folder(folder_id, access_token):
	[succedded, response] = make_request(settings["SDK_URL_FORMAT"] % ('%s/files?access_token=%s' % (folder_id, access_token)))
	if succedded:
		files = process_folder_response(response, access_token)
		#print json.dumps(files, indent = 4)
		return files
	return error_page(response["code"], response["message"])

def process_folder_response(response, access_token):
	files = []
	if not("data" in response):
		return files
	
	for file in response["data"]:
		#print json.dumps(file, indent = 4)
		if file["type"] == "file" and "name" in file:
			file_name, file_extension = os.path.splitext(file["name"])
			files.append({'name': file_name, \
				'link': file["upload_location"], \
				'updated_time': file["updated_time"], #datetime.strftime("%Y-%d-T%H:%M", file["updated_time"]), \ #2015-01-15T20:10:00+0000
				'content': read_file(file['upload_location'], access_token) })
		elif file["type"] == "folder":
			files += read_app_folder(file["id"], access_token)

	return files

def read_file(file_link, access_token):
	[succedded, response] = make_request('%s?surpress_redirects=true&access_token=%s' % (file_link, access_token), raw = True)
	if succedded:
		return response
	return error_page(response["code"], response["message"])

### ### ### ### ### Request utilities ### ### ### ### ###
def make_request(request, raw = False):
	try:
		logger.info('Making a request %s', request)
		response = urllib2.urlopen(request)
		
		if raw:
			return [True, response.read()]
		else:
			parsed_response = json.loads(response.read())
			return [True, parsed_response]
	except urllib2.URLError, e:
		return [False, {"code": e.code, "message": e.read()}]

def register(username, name, agreed):
	logger.info('Trying to register for user_id %s, username %s and name %s', username, name)
	if not(session['user_id']):
		return [False, 'There is a problem with user account. Please try logging again by going to homepage.']
	
	if not(agreed):
		return [False, 'You need to agree the terms.']
	if len(username) < 4 and len(name) < 5:
		return [False, 'Please check the values entered for username and name.']

	logger.info('Trying to register username %s and name %s for user_id %s', username, name, session['user_id'])
	if username and name:
		if is_username_registered(username):
			return [False, 'Username is already in use. Please select another username and try again.']

		logger.info('Registering user_id %s, username %s and name %s', session['user_id'], username, name)
		session['username'] = username
		session['name'] = name
		
		if save_user(session['user_id'], username, name):
			return [True, 'Successfully registered']
		else:
			return [False, 'An error occured while registering the user. Please try again later.']
	else:
		return [False, 'There is a problem with username or password']

### ### ### ### ###  User related methods ### ### ### ### ###
def is_user_registered(user_id, access_token):
	logger.info('Login is requested for user_id %s', user_id)
	session['user_id'] = user_id
	session['access_token'] = access_token
	
	# Go to DB and check if user is already registered or not
	user = db.find_one({ 'user_id': user_id })
	if user_id and access_token and user:
		logger.info('user_id %s is already registered', user_id)
		
		session['_id'] = str(user['_id'])
		session['username'] = str(user['username'])
		session['name'] = str(user['name'])
		return True
		
	logger.info('user_id %s is not yet registered', user_id)
	return False

def is_username_registered(username):
	users = db.find({ 'username': username })
	return users.count() > 0

def save_files(user_id, files):
	result = db.insert({ 'user_id': user_id, 'username': username, 'name': name })
	print result
	return result is not None
	
def save_user(user_id, username, name):
	result = db.insert({ 'user_id': user_id, 'username': username, 'name': name, 'files': [] })
	if result is not None:
		session['_id'] = str(result)
		return True
	return False

### ### ### ### ### Helpers ### ### ### ### ###
def error_page(code, message):
	return render_template("error.html", title = '%s Error' % str(code), subtitle = "Something went wrong!", message = message)

def logged_in():
	return ('user_id' in session) and ('access_token' in session) and (session['user_id']) and (session['access_token'])
	
if __name__ == "__main__":
	app.run()