import os
import json
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import base64

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set the user password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify the password against the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self, include_posts=False):
        """Convert user object to dictionary"""
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'bio': self.bio,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_active': self.is_active
        }
        
        if include_posts:
            user_dict['posts'] = [post.to_dict(include_author=False) for post in self.posts]
        
        return user_dict
    
    def __repr__(self):
        return f'<User {self.username}>'


class Post(db.Model):
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.String(500), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_published = db.Column(db.Boolean, default=False, nullable=False)
    view_count = db.Column(db.Integer, default=0, nullable=False)
    tags = db.Column(db.String(500), nullable=True)
    
    def to_dict(self, include_author=True):
        """Convert post object to dictionary"""
        post_dict = {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'excerpt': self.excerpt,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_published': self.is_published,
            'view_count': self.view_count,
            'tags': self.tags.split(',') if self.tags else []
        }
        
        if include_author:
            post_dict['author'] = {
                'id': self.author.id,
                'username': self.author.username,
                'email': self.author.email
            }
        else:
            post_dict['author_id'] = self.author_id
        
        return post_dict
    
    def __repr__(self):
        return f'<Post {self.title}>'


def get_auth_credentials():
    """Extract and decode basic authentication credentials from request"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Basic '):
        return None, None
    
    try:
        encoded_credentials = auth_header[6:]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':', 1)
        return username, password
    except (ValueError, TypeError):
        return None, None


def require_auth(f):
    """Decorator to require basic authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username, password = get_auth_credentials()
        
        if not username or not password:
            return jsonify({
                'success': False,
                'message': 'Missing or invalid authentication credentials',
                'error': 'Unauthorized'
            }), 401
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return jsonify({
                'success': False,
                'message': 'Invalid username or password',
                'error': 'Unauthorized'
            }), 401
        
        if not user.is_active:
            return jsonify({
                'success': False,
                'message': 'User account is inactive',
                'error': 'Forbidden'
            }), 403
        
        request.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function


@app.before_request
def before_request():
    """Initialize database tables if they don't exist"""
    pass


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'message': 'Resource not found',
        'error': 'Not Found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return jsonify({
        'success': False,
        'message': 'Internal server error',
        'error': 'Internal Server Error'
    }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'API is running',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user"""
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'message': 'Request body must be JSON',
            'error': 'Bad Request'
        }), 400
    
    required_fields = ['username', 'email', 'password']
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return jsonify({
            'success': False,
            'message': f'Missing required fields: {", ".join(missing_fields)}',
            'error': 'Bad Request'
        }), 400
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    bio = data.get('bio', '').strip()
    
    if not username or len(username) < 3:
        return jsonify({
            'success': False,
            'message': 'Username must be at least 3 characters long',
            'error': 'Bad Request'
        }), 400
    
    if not email or '@' not in email:
        return jsonify({
            'success': False,
            'message': 'Invalid email format',
            'error': 'Bad Request'
        }), 400
    
    if not password or len(password) < 6:
        return jsonify({
            'success': False,
            'message': 'Password must be at least 6 characters long',
            'error': 'Bad Request'
        }), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({
            'success': False,
            'message': 'Username already exists',
            'error': 'Conflict'
        }), 409
    
    if User.query.filter_by(email=email).first():
        return jsonify({
            'success': False,
            'message': 'Email already exists',
            'error': 'Conflict'
        }), 409
    
    user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        bio=bio
    )
    user.set_password(password)
    
    try:
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'data': user.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error creating user',
            'error': str(e)
        }), 500


@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    if page < 1 or per_page < 1:
        return jsonify({
            'success': False,
            'message': 'Page and per_page must be positive integers',
            'error': 'Bad Request'
        }), 400
    
    if per_page > 100:
        per_page = 100
    
    pagination = User.query.paginate(page=page, per_page=per_page, error_out=False)
    
    users = [user.to_dict() for user in pagination.items]
    
    return jsonify({
        'success': True,
        'message': 'Users retrieved successfully',
        'data': users,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    }), 200


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user by ID"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({
            'success': False,
            'message': f'User with ID {user_id} not found',
            'error': 'Not Found'
        }), 404
    
    include_posts = request.args.get('include_posts', 'false').lower() == 'true'
    
    return jsonify({
        'success': True,
        'message': 'User retrieved successfully',
        'data': user.to_dict(include_posts=include_posts)
    }), 200


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    """Update a user"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({
            'success': False,
            'message': f'User with ID {user_id} not found',
            'error': 'Not Found'
        }), 404
    
    if request.current_user.id != user_id and not is_admin(request.current_user):
        return jsonify({
            'success': False,
            'message': 'You do not have permission to update this user',
            'error': 'Forbidden'
        }), 403
    
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'message': 'Request body must be JSON',
            'error': 'Bad Request'
        }), 400
    
    if 'email' in data:
        email = data['email'].strip()
        if email != user.email and User.query.filter_by(email=email).first():
            return jsonify({
                'success': False,
                'message': 'Email already exists',
                'error': 'Conflict'
            }), 409
        user.email = email
    
    if 'first_name' in data:
        user.first_name = data['first_name'].strip()
    
    if 'last_name' in data:
        user.last_name = data['last_name'].strip()
    
    if 'bio' in data:
        user.bio = data['bio'].strip()
    
    if 'password' in data:
        password = data['password']
        if len(password) < 6:
            return jsonify({
                'success': False,
                'message': 'Password must be at least 6 characters long',
                'error': 'Bad Request'
            }), 400
        user.set_password(password)
    
    try:
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'data': user.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error updating user',
            'error': str(e)
        }), 500


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({
            'success': False,
            'message': f'User with ID {user_id} not found',
            'error': 'Not Found'
        }), 404
    
    if request.current_user.id != user_id and not is_admin(request.current_user):
        return jsonify({
            'success': False,
            'message': 'You do not have permission to delete this user',
            'error': 'Forbidden'
        }), 403
    
    try:
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully',
            'data': {'id': user_id}
        }), 200
    except