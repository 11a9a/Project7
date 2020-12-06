from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

app = Flask(__name__)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
app.config['SECRET_KEY'] = 'some_secret_key'
jwt = JWTManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./app.db'
db = SQLAlchemy(app)

class User(db.Model):
	id 				= db.Column(db.Integer, primary_key=True)
	email 			= db.Column(db.String(50), unique=True, nullable=False)
	name 			= db.Column(db.String(50))
	password 		= db.Column(db.String(80))
	profile_picture = db.Column(db.Text)

class Task(db.Model):
	id 			= db.Column(db.Integer, primary_key=True)
	title 		= db.Column(db.String(50), nullable=False)
	course 		= db.Column(db.String(50))
	endTask 	= db.Column(db.String(50))
	status 		= db.Column(db.String(50))
	description = db.Column(db.Text)
	isExam 		= db.Column(db.Boolean)
	userId 		= db.Column(db.Integer)

class Course(db.Model):
	id 			= db.Column(db.Integer, primary_key=True)
	title 		= db.Column(db.String(50), nullable=False)
	startTime 	= db.Column(db.String(50))
	endTime 	= db.Column(db.String(50))
	startDate 	= db.Column(db.String(50))
	endDate 	= db.Column(db.String(50))
	description = db.Column(db.Text)
	day 		= db.Column(db.String(25))
	userId 		= db.Column(db.Integer)


#Tasks
@app.route('/task', methods=['POST'])
@jwt_required
def create_task():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	data = request.get_json()

	new_task = Task(title=data['title'], course=data['course'], endTask=data['endTask'], status='created', isExam=data['isExam'], description=data['description'], userId=userId)

	db.session.add(new_task)
	db.session.commit()

	return jsonify({'msg':'Task has been created!'})

@app.route('/task', methods=['GET'])
@jwt_required
def get_all_tasks():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	tasks = Task.query.filter_by(userId=userId)

	output = []

	for task in tasks:
		if task.status == 'deleted':
			continue
		task_data = {}
		task_data['id'] = task.id
		task_data['title'] = task.title
		task_data['course'] = task.course
		task_data['endTask'] = task.endTask
		task_data['status'] = task.status
		task_data['isExam'] = task.isExam
		task_data['description'] = task.description
		output.append(task_data)

	return jsonify({'tasks': output})

@app.route('/task/created', methods=['GET'])
@jwt_required
def get_created_tasks():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	tasks = Task.query.filter_by(userId=userId, status='created')

	output = []

	for task in tasks:
		task_data = {}
		task_data['id'] = task.id
		task_data['title'] = task.title
		task_data['course'] = task.course
		task_data['endTask'] = task.endTask
		task_data['status'] = task.status
		task_data['isExam'] = task.isExam
		task_data['description'] = task.description
		output.append(task_data)

	return jsonify({'tasks': output})

@app.route('/task/started', methods=['GET'])
@jwt_required
def get_started_tasks():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	tasks = Task.query.filter_by(userId=userId, status='started')

	output = []

	for task in tasks:
		task_data = {}
		task_data['id'] = task.id
		task_data['title'] = task.title
		task_data['course'] = task.course
		task_data['endTask'] = task.endTask
		task_data['status'] = task.status
		task_data['isExam'] = task.isExam
		task_data['description'] = task.description
		output.append(task_data)

	return jsonify({'tasks': output})

@app.route('/task/done', methods=['GET'])
@jwt_required
def get_done_tasks():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	tasks = Task.query.filter_by(userId=userId, status='done')

	output = []

	for task in tasks:
		task_data = {}
		task_data['id'] = task.id
		task_data['title'] = task.title
		task_data['course'] = task.course
		task_data['endTask'] = task.endTask
		task_data['status'] = task.status
		task_data['isExam'] = task.isExam
		task_data['description'] = task.description
		output.append(task_data)

	return jsonify({'tasks': output})

@app.route('/task', methods=['DELETE'])
@jwt_required
def delete_task():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	task_id = request.args.get('id')

	task = Task.query.filter_by(id=task_id).first()

	if not task:
		return jsonify({'msg': 'Task not found'})

	if userId == task.userId:
		task.status = 'deleted'
		db.session.commit()
		return jsonify({'msg': 'Task has been deleted!'})

	return jsonify({'msg': 'Bad request'})


@app.route('/task', methods=['PUT'])
@jwt_required
def update_status():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	task_id = request.args.get('id')
	status = request.args.get('status')

	task = Task.query.filter_by(id=task_id).first()

	if userId == task.userId:
		task.status = status
		db.session.commit()
		return jsonify({'msg': 'Status has been updated!'})

	return jsonify({'msg': 'Failed!'})


#Courses
@app.route('/course', methods=['POST'])
@jwt_required
def create_course():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	data = request.get_json()

	new_course = Course(title=data['title'], startTime=data['startTime'], endTime=data['endTime'], startDate=data['startDate'], endDate=data['endDate'], description=data['description'], day=data['day'], userId=userId)

	db.session.add(new_course)
	db.session.commit()

	return jsonify({'msg':'Course has been created!'})

@app.route('/course', methods=['GET'])
@jwt_required
def get_all_courses():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	courses = Course.query.filter_by(userId=userId)

	output = []

	for course in courses:
		course_data = {}
		course_data['id'] = course.id
		course_data['title'] = course.title
		course_data['startTime'] = course.startTime
		course_data['endTime'] = course.endTime
		course_data['startDate'] = course.startDate
		course_data['endDate'] = course.endDate
		course_data['description'] = course.description
		course_data['day'] = course.day
		output.append(course_data)

	return jsonify({'courses': output})

@app.route('/course', methods=['DELETE'])
@jwt_required
def delete_course():
	current_user = get_jwt_identity()
	userId = User.query.filter_by(email=current_user).first().id

	course_id = request.args.get('id')

	course = Course.query.filter_by(id=course_id).first()

	if userId == course.userId:
		db.session.delete(course)
		db.session.commit()
		return jsonify({'msg': 'Course has been deleted!'})

	return jsonify({'msg': 'Failed!'})


#Users
@app.route('/user', methods=['PUT'])
@jwt_required
def update_profile_picture():
	current_user = get_jwt_identity()
	user = User.query.filter_by(email=current_user).first()

	profile_picture = request.args.get('profile_picture')

	user.profile_picture = profile_picture
	db.session.commit()
	return jsonify(profile_picture=profile_picture)

@app.route('/user/update', methods=['PUT'])
@jwt_required
def update_user():
	current_user = get_jwt_identity()
	user = User.query.filter_by(email=current_user).first()

	name = request.json.get('name', user.name)
	password = request.json.get('password', user.password)

	hashed_password = generate_password_hash(password, method='sha256')

	user.name = name
	user.password = hashed_password
	db.session.commit()
	return jsonify(name=name, password=password)

@app.route('/user', methods=['GET'])
@jwt_required
def get_user_info():
	current_user = get_jwt_identity()
	user = User.query.filter_by(email=current_user).first()

	return jsonify(name=user.name, email=user.email, profile_picture=user.profile_picture)


#Login/Register
@app.route('/register', methods=['POST'])
def register():
	email = request.json.get('email', None)
	password = request.json.get('password', None)
	name = request.json.get('name', None)
	profile_picture = request.json.get('profile_picture', None)

	if not email:
		return jsonify({'msg': 'Missing email!'}), 401

	if not password:
		return jsonify({'msg': 'Missing password!'}), 401

	hashed_password = generate_password_hash(password, method='sha256')

	new_user = User(email=email, name=name, password=hashed_password, profile_picture=profile_picture)

	db.session.add(new_user)
	db.session.commit()

	return jsonify({'msg': 'Registered successfully!'}), 200

@app.route('/login', methods=['POST'])
def login():
	email = request.json.get('email', None)
	password = request.json.get('password', None)

	if not email:
		return jsonify({'msg': 'Missing email!'}), 401

	if not password:
		return jsonify({'msg': 'Missing password!'}), 401

	user = User.query.filter_by(email=email).first()

	if not user:
		return jsonify({'msg': 'Email or Password is incorrect!'}), 401

	if check_password_hash(user.password, password):
		access_token = create_access_token(identity=email)
		return jsonify(access_token=access_token), 201

	return jsonify({'msg': 'Email or Password is incorrect!'}), 401


if __name__ == '__main__':
	app.run(debug=True)