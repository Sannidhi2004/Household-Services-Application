from flask_sqlalchemy import SQLAlchemy
from flask_security import RoleMixin, UserMixin, SQLAlchemyUserDatastore
from datetime import datetime
 

db = SQLAlchemy()

class test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.Integer)

class test2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100))
    phone_no = db.Column(db.Integer)


class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean)
    fs_uniquifier = db.Column(db.String(255), unique=True)
    roles = db.relationship('Role', secondary='roles_users',
                            backref=db.backref('users', lazy='dynamic')) 

class ServiceProvider(db.Model):
    __tablename__ = 'ServiceProvider'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    service_name = db.Column(db.String(255), nullable=False)
    experience = db.Column(db.Integer, nullable=False)


class PendingServiceRequest(db.Model):
    __tablename__ = 'pending_service_requests'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hash in production
    service_name = db.Column(db.String(255), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(255), nullable=True)  # Optional
    service_name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="Pending")  # Default status

    def __init__(self, service_name, description, base_price, image=None, status="Pending"):
        self.service_name = service_name
        self.description = description
        self.base_price = base_price
        self.image = image
        self.status = status 
        
class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('ServiceProvider.id'), nullable=True)
    status = db.Column(db.String(20), default="Requested")  # "Requested", "Assigned", "Completed"
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    date_of_completion = db.Column(db.DateTime, nullable=True)  # Optional
    remarks = db.Column(db.Text, nullable=True)  
    completion_status = db.Column(db.String(50), nullable=True)  

    # Relationships
    service = db.relationship('Service', backref='requests')
    customer = db.relationship('User', backref='customer_requests')
    professional = db.relationship('ServiceProvider', backref='assigned_requests', lazy=True)
        
class roles_users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id')) 

user_datastore = SQLAlchemyUserDatastore(db, User, Role)

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, nullable=False)  # ID of the flagged item
    item_type = db.Column(db.String(50), nullable=False)  # 'service', 'customer', or 'provider'
    reason = db.Column(db.String(255), nullable=True)  # Optional reason for flagging
    flagged_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Flag {self.item_type} {self.item_id}>"

    def to_dict(self):
        return {
            "id": self.id,
            "item_id": self.item_id,
            "item_type": self.item_type,
            "reason": self.reason,
            "flagged_at": self.flagged_at.strftime("%Y-%m-%d %H:%M:%S"),
        }