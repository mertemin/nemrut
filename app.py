from flask import current_app as app, flash, Flask, jsonify, Markup, redirect, render_template, redirect, request, session, url_for
import os, dateutil.parser, datetime, json, logging, markdown, urllib, urllib2, pymongo
from bson.objectid import ObjectId

app = Flask(__name__)
app.config.from_object('config')

logging.basicConfig(level = logging.DEBUG)
logger = logging.getLogger(__name__)

mongo_client = pymongo.MongoClient(app.config["MONGODB_URI"])
client_db = mongo_client.get_default_database()
db = client_db[app.config["NAME"]]

@app.route('/')
def index():
	if logged_in():
		return redirect(url_for('home'))
	return render_template("login.html", login_url = app.config["LOGIN_URL_FORMAT"] % (app.config["CLIENT_ID"], app.config["CLIENT_SCOPE"], app.config["REDIRECT_URI"]))

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
	
	[error_msg, user] = read_user(session['username'])
	return render_template("home.html", subtitle = session['username'], title = session['name'], user_id = session['user_id'], response = error_msg, files = user['files'])

@app.route('/sync')
def sync():
	[succedded, response] = make_request(app.config["SDK_URL_FORMAT"] % ('drive/root:/nemrut:/children?access_token=%s' % session['access_token']))

	if succedded:
		files = process_files(response)
		db.update({ '_id': ObjectId(session['_id']) },  { '$set': { 'files': files } })
		return redirect(url_for('home'))
	elif "itemNotFound" in response["message"]:
		create_app_folder(session['access_token'])
		return redirect(url_for('home'))
	return error_page(response["code"], response["message"])

@app.route("/user/<username>")
def blog(username):
	[error_msg, user] = read_user(username)
	if user:
		return render_template("user.html", title = user['name'], subtitle = user['username'], username = username, files = user['files'])
	
	return error_page(404, "User cannot be found")
	
@app.route("/post/<username>/<title>")
def read(username, title):
	users = db.find({ 'username': username })
	if users.count() > 0:
		user = users[0]
		for file in user['files']:
			if file['name'] == title:
				content = read_file(file["direct_link"]) if "direct_link" in file else file["content"] 
				return render_template("post.html", content = Markup(markdown.markdown(content)), title = file['name'], time = file['updated_time'], username = user['username'], subtitle = user['name'])
	
	return error_page(404, "Content cannot be found")

### ### ### ### ### Live SDK related methods ### ### ### ### ###
def create_auth_request(request):
	logger.info('Auth is requested')

	code = request.args.get('code', '')
	values = {'client_id': app.config["CLIENT_ID"], 'redirect_uri': app.config["REDIRECT_URI"], 'client_secret': app.config["CLIENT_SECRET"], 'code': code, 'grant_type': app.config["GRANT_TYPE"]}
	data = urllib.urlencode(values)
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}
	return urllib2.Request(app.config["AUTH_URL"], data, headers)

def create_app_folder(access_token):
	logger.info('Creating the folder')
	data = json.dumps({'name': app.config["NAME"], 'folder': {}})
	headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer %s' % access_token}
	post_request = urllib2.Request(app.config["SDK_URL_FORMAT"] % 'drive/root/children', data, headers)
	
	[succedded, response] = make_request(post_request)
	print response
	if succedded:
		return redirect(url_for('home'))
	return error_page(response["code"], response["message"])

def process_files(response):
	files = []
	if not("value" in response):
		return files
	
	for file in response["value"]:
		if "file" in file and "mimeType" in file["file"] and file["file"]["mimeType"] == "text/plain" and "name" in file:
			update_time = dateutil.parser.parse(file["lastModifiedDateTime"])
			file_name, file_extension = os.path.splitext(file["name"])
			files.append({'name': file_name, \
				'direct_link': file['@content.downloadUrl'],
				'updated_time': update_time.strftime("%m-%d-%Y %H:%M"), \
				'content': "" }) #Skip read file read_file(file['@content.downloadUrl'])
		#elif file["folder"] == "folder":
		#	files += read_app_folder(file["id"], access_token)

	return files

def read_file(file_link):
	[succedded, response] = make_request(file_link, raw = True)
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
	logger.info('Trying to register for username %s and name %s', username, name)
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
			create_app_folder(session['access_token'])
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

def read_user(username):
	user = db.find_one({ 'username': username })
	if user:
		return ["", user]
	return ["There is a problem reading files.", {}]

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
	action_link = ""
	if "request_token_expired" in message:
		action_link = app.config["LOGIN_URL_FORMAT"] % (app.config["CLIENT_ID"], app.config["CLIENT_SCOPE"], app.config["REDIRECT_URI"])
	return render_template("error.html", title = '%s Error' % str(code), subtitle = "Something went wrong!", message = message, action_link = action_link)

def logged_in():
	return ('user_id' in session) and ('access_token' in session) and (session['user_id']) and (session['access_token'])
	
if __name__ == "__main__":
	app.run()