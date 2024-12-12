from flask import Flask, request, session, jsonify
from datetime import timedelta
from flask_jwt_extended import create_access_token, decode_token, JWTManager, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'Hello World!'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.secret_key = 'asdsadsada'

jwt = JWTManager(app)

tasks = [
        {
           '_id': 1,
           'title': 'doing Homework this 10pm!',
           'description':'will do homework for ITCC 41 and ITCC 31',
           'date': '12-10-2024',
           'status': 'pending'
        },
        {
           '_id': 2,
           'title': 'Study then Valorant!',
           'description':'Studying ITCC 14 and pass, then Valorant',
           'date': '12-12-2024',
           'status': 'pending'
        }
    ]
    
users = []
status_valid = ['pending', 'ongoing','completed']

def getNextID():
    Task = []
    for task in tasks:
        Task = task
        
    return Task['_id'] + 1
    
    
@app.route('/tasks', methods=['GET', 'POST'])
def getAll():
    if request.method == 'GET':
        try:
            title = request.args.get('title')
            date = request.args.get('date')
            status = request.args.get('status')
            counter = 0
            response = []
            
            if not title and not date and not status:
                for item in tasks: 
                    response.append(item)
                    
                    
            for item in tasks:
                if title is not None:
                    if title == item['title']:
                        response.append(item)
                if date is not None:
                    if date == item['date']:
                        response.append(item)
                if status is not None:
                    if status == item['status']:
                        response.append(item)
                counter = counter + 1
            
            return jsonify(response)
        except Exception as e:
            return jsonify({'error': (e)}), 401
    
    if request.method == 'POST':
        try:
            if not request.is_json:
                return jsonify({'error': 'payload must be in json format'}), 401
                
            task_data = request.get_json()
            title = task_data.get('title')
            description = task_data.get('description')
            date = task_data.get('date')
            status = task_data.get('status')
            
            if status not in status_valid:
                return jsonify({'error': 'Invalid status'}), 401
               
            new_task = {
                    '_id': getNextID(),
                    'title': title,
                    'description': description,
                    'date': date,
                    'status': status
                }
            
            tasks.append(new_task)
            
            return jsonify({'message':'Task added successful.'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 401


@app.route('/tasks/<int:task_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@jwt_required()
def getSpecific(task_id):
    if request.method == 'GET':
        for task in tasks: 
            if task['_id'] == task_id:
                Task = task
                return jsonify(Task), 200
                
    if request.method == 'PUT' or request.method == 'PATCH':
        try:
            if not request.is_json:
                return jsonify({'error': 'format must be in json'}), 401
            
            task_data = request.get_json()
            title = task_data.get('title')
            date = task_data.get('date')
            status = task_data.get('status')
            
            for item in tasks:
                if item['_id'] == task_id:
                    if title is not None:
                        item['title'] = title
                    if date is not None:
                        item['date'] = date
                    if status is not None:
                        item['status'] = status
                    
                    return jsonify({'message': 'update successful'}), 200
            
        except Exception as e:
            return jsonify({'error': str(e)}), 401
            
    if request.method == 'DELETE':
        counter = 0
        for item in tasks:
            if item['_id'] == task_id:
                tasks.pop(item['_id']-1)
                return jsonify({'message': 'delete successful'}), 200
            else:
                counter = counter + 1


@app.route('/users/create', methods=['POST'])
def userCreate():
    try:
        if not request.is_json:
            return jsonify({'error': 'format must be in json'})
        
        user_data = request.get_json()
        username = user_data.get('username')
        password = user_data.get('password')
        name = user_data.get('name')
        
        if not username or not password or not name:
            return jsonify({'error': 'username, password and name are all required fields.'}), 401
            
        hashpass = generate_password_hash(password)
        
        for item in users:
            if item['username'] == username:
                return jsonify({'error': 'username unavailable.'}), 401
        
        
        new_account = {
            'username': username,
            'password': hashpass,
            'name': name
        }
        
        users.append(new_account)
        print(users)
        return jsonify({'message': 'account registered successfuly.'}), 200
    except Exception as e:
        return jsonify({'error': (e)}), 401


@app.route('/users/login', methods=['POST'])
def userLogin():
    try:
        if not request.is_json:
            return jsonify({'error': 'format must be in json'}), 400
        
        user_data = request.get_json()
        username = user_data.get('username')
        password = user_data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'username and password are required.'}), 400
        
        for item in users:
            if item['username'] == username:
                if check_password_hash(item['password'], password):
                    apiKey = create_access_token(identity=username)
                    return jsonify({'message': 'Login successful.'}, {'apikey': apiKey}), 200
                    
        return jsonify({'error': 'Invalid username and password.'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
       

@app.route('/users', methods=['GET'])
def getUsers():
        return jsonify(users)
        
if __name__ == '__main__':
    app.run(debug=True)
