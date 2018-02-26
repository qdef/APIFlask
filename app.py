from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///apiblog.db'

db = SQLAlchemy(app)

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	public_id = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50))
	password=db.Column(db.String(50))
	admin = db.Column(db.Boolean)
	
class BlogPost(db.Model):
	post_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	title = db.Column(db.String(150))
	author = db.Column(db.String(50))
	created = db.Column(db.DateTime)
	content = db.Column(db.Text)

#__________________________USERS MANAGEMENT_____________________________

def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'message': 'Token is missing!'}), 401
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'message': 'Token is invalid!'}), 401
		return f(current_user, *args, **kwargs)
	return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
	if not current_user.admin:
		return jsonify({'message': 'Only admin users can perform that action.'})
	users = User.query.all()
	output = []
	for user in users:
		user_data={}
		user_data['public_id']=user.public_id
		user_data['name']=user.name
		user_data['password']=user.password
		user_data['admin']=user.admin
		output.append(user_data)
	return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message': 'Only admin users can perform that action.'})	
	user = User.query.filter_by(public_id=public_id).first()
	if not user:
		return jsonify({'message': 'No user found!'})
	user_data={}
	user_data['public_id']=user.public_id
	user_data['name']=user.name
	user_data['password']=user.password
	user_data['admin']=user.admin
	return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
	if not current_user.admin:
		return jsonify({'message': 'Only admin users can perform that action.'})	
	data = request.get_json()
	hashed_password = generate_password_hash(data['password'], method='sha256')
	new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
	db.session.add(new_user)
	db.session.commit()
	return jsonify({'message': 'New user has been successfully created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message': 'Only admin users can perform that action.'})	
	user = User.query.filter_by(public_id=public_id).first()
	if not user:
		return jsonify({'message': 'No user found!'})
	user.admin = True
	db.session.commit()
	return jsonify({'message': 'The user has been promoted to admin.'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message': 'Only admin users can perform that action.'})	
	user = User.query.filter_by(public_id=public_id).first()
	if not user:
		return jsonify({'message': 'No user found!'})	
	db.session.delete(user)
	db.session.commit()
	return jsonify({'message': 'The user has been successfully deleted.'})

@app.route('/login')
def login():
	auth = request.authorization
	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
	user = User.query.filter_by(name=auth.username).first()
	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow()+ datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
		return jsonify({'token': token.decode('UTF-8')})
	return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


#__________________________POSTS MANAGEMENT_____________________________


@app.route('/blog', methods=['GET'])
@token_required
def all_posts(current_user):
	posts = BlogPost.query.all()
	output = []
	for post in posts:
		post_data = {}
		post_data['id'] = post.post_id
		post_data['title'] = post.title
		post_data['author'] = post.author
		post_data['created'] = post.created
		post_data['content'] = post.content
		output.append(post_data)
	return jsonify({'posts': output})

@app.route('/blog/<post_id>', methods=['GET'])
@token_required
def detail_post(current_user, post_id):
	posts = BlogPost.query.filter_by(post_id=post_id).first()
	if not posts:
		return jsonify({'message': 'No post was found!'})
	post_data = {}
	post_data['id'] = posts.post_id
	post_data['title'] = posts.title
	post_data['author'] = posts.author
	post_data['created'] = posts.created
	post_data['content'] = posts.content
	return  jsonify({'post': post_data})

@app.route('/blog', methods=['POST'])
@token_required
def create_post(current_user):
	data = request.get_json()
	new_post = BlogPost(title=data['title'], content=data['content'], author=current_user.name, created=datetime.datetime.utcnow() )
	db.session.add(new_post)
	db.session.commit()
	return jsonify({'message' : 'New post was successfully created!'})

@app.route('/blog/<post_id>', methods=['PUT'])
@token_required
def edit_post(current_user, post_id):
	post = BlogPost.query.filter_by(post_id=post_id, author=current_user.name).first()
	if not post:
		return jsonify({'message': 'No post was found!'})
	data = request.get_json()
	post.title = data['title']
	post.content = data['content']
	db.session.commit()
	return jsonify({'message': 'Post has been successfully updated!'})

@app.route('/blog/<post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
	post = BlogPost.query.filter_by(post_id=post_id, author=current_user.name).first()
	if not post:
		return jsonify({'message': 'No post was found!'})
	db.session.delete(post)
	db.session.commit()
	return jsonify({'message': 'Post has been successfully deleted.'})

#________________________________________________________________________________

if __name__ == '__main__':
	app.run(debug=True)
