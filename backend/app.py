from flask import Flask, request, jsonify, request
from flask_sqlalchemy import SQLAlchemy 
from models import db, test, user_datastore, Role, User, roles_users, test2, ServiceProvider, Service, ServiceRequest, PendingServiceRequest, Flag
from flask_security import Security, auth_required, roles_accepted, current_user
from config import Config, localdev
from flask_cors import CORS, cross_origin
from models import db, user_datastore
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import uuid
import traceback  # Add this at the top
from caching import cache
from mailing import mail
from celery import Celery
from celery.schedules import crontab
from flask import Flask, request, jsonify
from datetime import datetime
from models import db, ServiceRequest
from flask_jwt_extended import jwt_required, get_jwt_identity



def create_app():
    app_init = Flask(__name__)
    app_init.config.from_object(localdev)  # Use the correct class
    db.init_app(app_init)
    mail.init_app(app_init)
    cache.init_app(app_init)
    CORS(app_init, resources={r"/*": {"origins": "http://localhost:8080"}}, 
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], supports_credentials=True),   
    # Flask-Security must be initialized AFTER db.init_app
    security = Security(app_init, user_datastore)

    return app_init


app=create_app()

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)



@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight successful"})
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:8080")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization, Authentication-Token")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

 
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:8080"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Authentication-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


def create_celery(app):
    celery_init=Celery(app.import_name)
    from config import celery_config
    celery_init.config_from_object(celery_config)
    celery_init.conf.beat_schedule = {
        'send-email-every-5-seconds': {
            'task': 'jobs.send_mail_task',
            'schedule': 5.0,  # Every 5 seconds
        },
        'send-pending-requests-every-20-seconds': {
            'task': 'jobs.send_pending_requests_email',
            'schedule': 20.0,  # Runs every 20 seconds
        },
        
    }
    return celery_init

celery_app= create_celery(app)
from jobs import *


from flask_mail import Message
'''
@app.route("/mail")
def index():
    def mails():
        msg = Message(
            subject="Hello",
            recipients=["to@example.com", "test@test.com"],
        )
        msg.body = "This is the email body"
        msg.html = "<h1>HTML</h1> body"
        mail.send(msg)
    mails()
    return "done"
'''



@app.route('/helloworld')
@auth_required('token')  # Ensure the user is authenticated
def hello_world():
    user = User.query.filter_by(email=request.headers.get('email')).first()
    if user:
        return {"msg": f'Hello, {user.email}!'}
    return {"msg": 'Hello, World!'}

@app.route('/firstApi', methods=['POST', 'GET', 'PUT', 'DELETE'])
@auth_required('token')
#@roles_accepted('customer')
def test1():
    if request.method == 'POST':
        if request.get_json(): # if request.form
            # var1 = request.get_json()['formKey'] # request.form['formKey']
            data = request.get_json()
            print(data)
            new_data = User(email=data['email'], password=data['password'])
            db.session.add(new_data)
            db.session.commit()
            return {"data": f'template print, {new_data.email}!'}
        return {"data": 'no data!'}
    
    if request.method == 'GET':
        data = User.query.first()
        if data:
            return {"data": data.email}
        return {"msg": 'This is a test API'}, 404
    
    if request.method == 'PUT':
        data = request.get_json()
        update_data = User.query.filter_by(id=data['id']).first()
        update_data.email = data['email']
        update_data.password = data['password']
        db.session.commit()
        return {"msg": 'Data updated', "email": f'{update_data.email}', "password": f'{update_data.password}'}
    
    if request.method == 'DELETE':
        data = request.get_json()
        delete_data = User.query.filter_by(id=data['id']).first()
        db.session.delete(delete_data)
        db.session.commit()
        return {"msg": 'Data deleted', "email": f'{delete_data.email}', "password": f'{delete_data.password}'}

@app.route('/secondApi', methods=['GET'])
@auth_required('token')

def test2():
    data = User.query.all()
    if data:
        return [{"email": i.email} for i in data]
    return {"msg": 'No data found'}, 404












@app.route('/api/login', methods=['POST'])
@cross_origin(origins="http://localhost:8080", supports_credentials=True)
def login():
    data = request.get_json()

    # Check if user exists in 'User' table
    user = user_datastore.find_user(email=data['email'])
    if user:
         # Check if user is flagged
        flagged_user = Flag.query.filter_by(item_id=user.id).first()
        if flagged_user:
            return {"msg": "Login failed. The admin has flagged this user."}, 403
        
        if user.password == data['password']:  # You should use bcrypt check (see below)
            role = user.roles[0].name  # Assuming a user has at least one role

            # Determine the redirect URL based on role
            if role == "admin":
                redirect_url = "/admin_dashboard"
            elif role == "customer":
                redirect_url = f"/customer_dashboard/{user.id}"                
            else:
                
                redirect_url = f"/service_professional_dashboard/{user.id}"

            return {
                "msg": "Login successful",
                "email": user.email,
                "user_id": user.id,
                "authToken": user.get_auth_token(),
                
                "role": role,
                "redirect": redirect_url
            }, 202

        return {"msg": "Invalid password"}, 417

    return {"msg": "User not found"}, 404





@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    print(f"DEBUG: Received Data: {data}")  # Log the request payload

    try:
        user = user_datastore.find_user(email=data['email'])
        print(f"DEBUG: Found existing user? {user}")  # Check if the user already exists

        if not user:
            new_user = user_datastore.create_user(email=data['email'], password=data['password'])
            db.session.commit()  # Commit user creation

            print(f"DEBUG: New user created: {new_user.email}")

            # Assign role based on received value
            if str(data['role']) == "2":
                user_datastore.add_role_to_user(new_user, 'Service_professional')
            elif str(data['role']) == "3":
                user_datastore.add_role_to_user(new_user, 'customer')

            db.session.commit()  # Commit again after role assignment
            print(f"DEBUG: Role assigned: {new_user.roles[0].name}")

            return {"msg": 'User created', "email": f'{new_user.email}', "role": f'{new_user.roles[0].name}'}, 201

        return {"msg": 'User found, use a different email'}, 409

    except Exception as e:
        print(f"ERROR: {e}")  # Print the error message in Flask logs
        return {"msg": "Internal Server Error", "error": str(e)}, 500  # Return error details


#to register the service_provider and send request to the admin
@app.route('/api/register_service', methods=['POST'])
def register_service_provider():
    data = request.get_json()

    try:
        # Check if email already exists in either User or ServiceProvider table
        if User.query.filter_by(email=data['email']).first() or ServiceProvider.query.filter_by(email=data['email']).first():
            return jsonify({"msg": "Service provider already exists"}), 409

        # Store request in pending_requests table for admin approval
        new_request = PendingServiceRequest(
            email=data['email'],
            password=data['password'],  # Hash password in production
            service_name=data['service_name'],
            experience=data['experience']
        )
        db.session.add(new_request)
        db.session.commit()

        return jsonify({
            "msg": "Registration request submitted for approval. Awaiting admin approval."
        }), 201

    except Exception as e:
        return jsonify({"msg": "Error processing request", "error": str(e)}), 500


#for the user (to be service provider) to see the services created by the admin during registration in a dropdown
@app.route("/api/servicesdropdown", methods=["GET"])
def get_services_dropdown():
    try:
        # Fetch all services
        services = Service.query.all()

        # Fetch flagged services
        flagged_service_ids = {flag.item_id for flag in Flag.query.filter_by(item_type="service").all()}

        # Filter out flagged services
        available_services = [
            {"id": service.id, "name": service.service_name}
            for service in services
            if service.id not in flagged_service_ids
        ]

        return jsonify(available_services), 200
    except Exception as e:
        print("Error fetching services dropdown:", str(e))
        return jsonify({"error": str(e)}), 500




#----------------------ADMIN DASHBOARD-----------------------------------

#for admin to see the pending requests
@app.route('/api/admin/pending_requests', methods=['GET'])
def get_pending_requests():
    try:
        pending_requests = PendingServiceRequest.query.all()
        return jsonify([
            {
                "id": request.id,
                "email": request.email,
                "service_name": request.service_name,
                "experience": request.experience
            }
            for request in pending_requests
        ]), 200
    except Exception as e:
        return jsonify({"msg": "Error fetching pending requests", "error": str(e)}), 500



#for admin- to approve the pending request
@app.route('/api/admin/approve_service', methods=['POST'])
def approve_service():
    data = request.get_json()
    request_entry = PendingServiceRequest.query.get(data['request_id'])

    if not request_entry:
        return jsonify({"msg": "Request not found"}), 404

    try:
        print(f"Approving request for: {request_entry.email}")  # Debugging log

        # Create user
        new_user = user_datastore.create_user(
            email=request_entry.email, 
            password=request_entry.password,  # Check if password exists
            active=True,
            fs_uniquifier=str(uuid.uuid4())
        )
        db.session.commit()

        print(f"Created user: {new_user.id}")  # Debugging log

        # Assign role
        user_datastore.add_role_to_user(new_user, 'Service_professional')
        db.session.commit()

        print(f"Assigned role to user: {new_user.id}")  # Debugging log

        # Create service provider
        new_provider = ServiceProvider( 
            email=request_entry.email,
            password=request_entry.password,  # Store hashed password in production
            service_name=request_entry.service_name,
            experience=request_entry.experience
        )

        db.session.add(new_provider)
        db.session.delete(request_entry)
        db.session.commit()

        print(f"Approved service provider: {new_provider.id}")  # Debugging log

        return jsonify({
            "msg": "Service provider approved and added",
            "user_id": new_user.id,
            "service_provider_id": new_provider.id
        }), 200

    except Exception as e:
        db.session.rollback()
        print("Error approving service provider:", str(e))  # Log the error
        print(traceback.format_exc())  # Print full error traceback
        return jsonify({"msg": "Approval failed", "error": str(e)}), 500



#for admin- to create a new service
@app.route('/api/create_service', methods=['POST'])
def create_service():
    data = request.get_json()
    service_name = data.get("service_name")

    # Check if the service already exists
    existing_service = Service.query.filter_by(service_name=service_name).first()
    if existing_service:
        return jsonify({"msg": "Service name already exists!"}), 400  # 400 = Bad Request

    
    new_service = Service(
        service_name=data['service_name'],
        description=data['description'],
        base_price=data['base_price'],
        image=data.get('image'),  # Optional
        status="Pending"
    )
    
    db.session.add(new_service)
    db.session.commit()
    
    return {"msg": "Service created successfully", "service_id": new_service.id}, 201

#for admin-to update the services
@app.route('/api/services/<int:service_id>', methods=['PUT'])
@cross_origin(origins="http://localhost:8080")
def update_service(service_id):
    service = Service.query.get(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404

    data = request.json
    service.description = data.get("description", service.description)
    service.base_price = data.get("base_price", service.base_price)

    try:
        db.session.commit()
        return jsonify({"message": "Service updated successfully!"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update service", "details": str(e)}), 500

#for admin-to delete the services
@app.route('/api/services/<int:service_id>', methods=['DELETE'])

def delete_service(service_id):
    service = Service.query.get(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404

    try:
        db.session.delete(service)
        db.session.commit()
        return jsonify({"message": "Service deleted successfully!"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete service", "details": str(e)}), 500

#for admin-to view services on the dashboard
@app.route("/api/services", methods=["GET"])

def get_services():
    token = request.headers.get("Authorization")  # Get token from request header
    print(f"Received Token: {token}")  # Debugging statement

    
    services = Service.query.all()
    return jsonify([{
        "id": service.id,
        "service_name": service.service_name,
        "description": service.description,
        "base_price": service.base_price,
        "status": service.status
    } for service in services])

#for admin-to view customers on the dashboard
@app.route("/api/customers", methods=["GET"])
def get_customers():
    customer_role = Role.query.filter_by(name="customer").first()
    if not customer_role:
        return jsonify([])  # No customers found
    customers = User.query.filter(User.roles.contains(customer_role)).all()
    return jsonify([{
        "id": user.id,
        "email": user.email,
        "active": user.active
    } for user in customers])

#for admin-to view service providers on the dashboard
@app.route("/api/service_providers", methods=["GET"])
def get_service_providers():
    providers = ServiceProvider.query.all()
    return jsonify([{
        "id": provider.id,
        "email": provider.email,
        "service_name": provider.service_name,
        "experience": provider.experience
    } for provider in providers])


#for admin- to add customers/services to the flag table
@app.route("/api/flag", methods=["POST"])
def flag_item():
    try:
        data = request.json
        print("Received flag request:", data)  # Debugging

        item_id = data.get("item_id")
        item_type = data.get("item_type")
        reason = data.get("reason", "")

        if not item_id or not item_type:
            print("Error: Missing required fields")
            return jsonify({"error": "Missing required fields"}), 400

        # Create a new flag entry
        new_flag = Flag(item_id=item_id, item_type=item_type, reason=reason)
        db.session.add(new_flag)
        db.session.commit()

        print("Item flagged successfully!")
        return jsonify({"message": "Item flagged successfully!"}), 201

    except Exception as e:
        db.session.rollback()
        print("Error in flag_item:", str(e))  # Debugging
        return jsonify({"error": str(e)}), 500


#to diaply the flagged items
@app.route("/api/flagged", methods=["GET"])
def get_flagged_items():
    try:
        flagged_items = Flag.query.all()
        flagged_list = [
            {"item_id": flag.item_id, "item_type": flag.item_type}
            for flag in flagged_items
        ]
        return jsonify(flagged_list), 200
    except Exception as e:
        print("Error fetching flagged items:", str(e))  # Debugging
        return jsonify({"error": str(e)}), 500




#for admin- to remove customers/services from the flag table
@app.route("/api/unflag", methods=["POST"])
def unflag_item():
    try:
        data = request.json
        print("Received unflag request:", data)  # Debugging

        item_id = data.get("item_id")
        item_type = data.get("item_type")

        if not item_id or not item_type:
            print("Error: Missing required fields")
            return jsonify({"error": "Missing required fields"}), 400

        # Find and delete the flag entry
        flag_entry = Flag.query.filter_by(item_id=item_id, item_type=item_type).first()
        if flag_entry:
            db.session.delete(flag_entry)
            db.session.commit()
            print("Item unflagged successfully!")
            return jsonify({"message": "Item unflagged successfully!"}), 200
        else:
            print("Flag entry not found!")
            return jsonify({"error": "Flag entry not found"}), 404

    except Exception as e:
        db.session.rollback()
        print("Error in unflag_item:", str(e))  # Debugging
        return jsonify({"error": str(e)}), 500






#----------------------CUSTOMER DASHBOARD-----------------------------------


@app.route("/services", methods=["GET",])
@auth_required("token")  # Ensure token-based authentication
@cross_origin(origins="http://localhost:8080")
def fetch_services():
    auth_header = request.headers.get("Authorization")
    print("Received Auth Header:", auth_header)  # Debugging

    services = Service.query.all()
    services_list = [
        {
            "id": s.id,
            "service_name": s.service_name,
            "description": s.description,
            "base_price": s.base_price,
            "status": s.status,
            "image": s.image if s.image else "default-image.jpg",
        }
        for s in services
    ]
    return jsonify(services_list)


@app.route("/api/service_requests/<int:request_id>/accept", methods=["PUT"])
def accept_service_request(request_id):
    data = request.get_json()
    user_id = data.get("user_id")  # Get the user ID from the frontend

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    # Fetch the service provider based on the user's ID
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    service_provider = ServiceProvider.query.filter_by(email=user.email).first()
    if not service_provider:
        return jsonify({"error": "Service provider not found"}), 404

    # Fetch the service request
    service_request = db.session.get(ServiceRequest, request_id)
    if not service_request:
        return jsonify({"error": "Service request not found"}), 404

    # Update the service request with professional_id and change status
    service_request.professional_id = service_provider.id
    service_request.status = "Accepted"

    # Commit changes to the database
    db.session.commit()

    return jsonify({
        "msg": "Service request accepted",
        "request_id": request_id,
        "status": "Accepted",
        "professional_id": service_provider.id
    })


#for customer- to view the customer requests in a table ['View Requests' on the customer navbar]
@app.route("/api/customer_requests/<int:userId>", methods=["GET"])
def get_customer_requests(userId):  
    requests = (
        db.session.query(ServiceRequest, Service)
        .join(Service, ServiceRequest.service_id == Service.id)
        .filter(ServiceRequest.customer_id == userId)
        .all()
    )
    requests_data = [
        {
            "id": req.ServiceRequest.id,
            "service_name": req.Service.service_name if req.Service else "Not Assigned",
            "professional_name": req.ServiceRequest.professional.service_name if req.ServiceRequest.professional else "Not Assigned",
            "status": req.ServiceRequest.status,
            "date_of_request": req.ServiceRequest.date_of_request.strftime("%Y-%m-%d"),
            "date_of_completion": req.ServiceRequest.date_of_completion.strftime("%Y-%m-%d") if req.ServiceRequest.date_of_completion else None  # ✅ Return None instead of "Pending"
        }
        for req in requests
    ]
    return jsonify(requests_data)


#for customer- to give remarks/ update service requests
@app.route("/api/update_request/<int:request_id>", methods=["PUT"])
def update_request(request_id):
    data = request.get_json()
    request_entry = ServiceRequest.query.get(request_id)

    if not request_entry:
        return jsonify({"error": "Request not found"}), 404

    request_entry.remarks = data.get("remarks", request_entry.remarks)

    db.session.commit()
    return jsonify({"message": "Request updated successfully", "remarks": request_entry.remarks})


#for customer- to delete service requests
@app.route("/api/delete_request/<int:request_id>", methods=["DELETE"])
def delete_request(request_id):
    request_entry = ServiceRequest.query.get(request_id)
    if not request_entry:
        return jsonify({"error": "Service request not found"}), 404

    db.session.delete(request_entry)
    db.session.commit()
    return jsonify({"message": "Service request deleted successfully"}), 200


#for customer- to close service requests
@app.route("/api/close_request/<int:request_id>", methods=["PUT"])
def close_request(request_id):
    request_entry = ServiceRequest.query.get(request_id)
    if not request_entry:
        return jsonify({"error": "Service request not found"}), 404

    request_entry.status = "Closed"
    db.session.commit()
    return jsonify({"message": "Service request closed successfully"}), 200



#---------------------------SERVICE PROFESSIONAL DASHBOARD-------------------


#to display service requests on a service_professional's dashboard
@app.route('/api/service_requests/<int:user_id>', methods=['GET'])
def service_requests(user_id):
    # Fetch user using SQLAlchemy
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404   
    # Find the service provider using the user's email
    service_provider = ServiceProvider.query.filter_by(email=user.email).first()
    if not service_provider:
        return jsonify({"msg": "Service provider not found"}), 404
    # Fetch service
    service = Service.query.filter_by(service_name=service_provider.service_name).first()
    if not service:
        return jsonify({"msg": "Service not found"}), 404
    # Fetch service requests related to this service
    service_requests = ServiceRequest.query.filter_by(service_id=service.id, status="Requested").all()
    # Extract customer IDs from service requests
    customer_ids = list(set(req.customer_id for req in service_requests))  
    # Fetch customer details
    customers = {user.id: user.email for user in User.query.filter(User.id.in_(customer_ids)).all()}
    # Debugging Outputs
    print(f"Service Provider ID: {service_provider.id} (User ID: {user_id})")
    print(f"Service name: {service_provider.service_name}")
    print(f"Service ID: {service.id}")
    print(f"Service Request IDs for Service ID {service.id}: {[req.id for req in service_requests]}")
    print(f"Customer IDs: {customer_ids}")
    print(f"Customer ID to Name Mapping: {customers}")
    # Prepare response
    response = {
        "service_requests": [
            {
                "id": req.id,
                "service_name": req.service.service_name,
                "customer_email": customers.get(req.customer_id, "Unknown"),
                "status": req.status,
                "date_of_request": req.date_of_request,
                "date_of_completion": req.date_of_completion
            }
            for req in service_requests
        ],
        "customer_mapping": customers
    }
    return jsonify(response)



#for service_professional to see accepted requests (their own)
@app.route("/api/accepted_requests/<int:user_id>", methods=["GET"])
def get_accepted_requests(user_id):
    print(f"Received request for accepted service requests of user_id: {user_id}")

    # Get the user's email from the User table
    user = User.query.filter_by(id=user_id).first()
    if not user:
        print(f"❌ User with id {user_id} not found")
        return jsonify({"error": "User not found"}), 404

    print(f"✅ Found user: {user.email}")

    # Find the corresponding ServiceProvider using email
    service_provider = ServiceProvider.query.filter_by(email=user.email).first()
    if not service_provider:
        print(f"❌ No matching ServiceProvider found for email: {user.email}")
        return jsonify({"error": "No matching service provider found"}), 404

    print(f"✅ Found ServiceProvider with id: {service_provider.id}")

    # Fetch accepted requests where professional_id matches the service_provider.id
    service_requests = ServiceRequest.query.filter_by(professional_id=service_provider.id).filter(
        ServiceRequest.status.in_(["Accepted"])
    ).all()

    if not service_requests:
        print(f"⚠️ No accepted requests found for ServiceProvider ID: {service_provider.id}")

    # Format response
    request_list = [
        {
            "id": req.id,
            "service_name": req.service.service_name,
            "customer_email": req.customer.email,
            "status": req.status,
            "date_of_request": req.date_of_request.strftime('%Y-%m-%d'),
            "date_of_completion": req.date_of_completion.strftime('%Y-%m-%d') if req.date_of_completion else None,
            "remarks": req.remarks
        }
        for req in service_requests
    ]

    print(f"📌 Returning {len(request_list)} accepted requests for ServiceProvider ID: {service_provider.id}")
    return jsonify(request_list)


#for service_professioanl to mark the accepted requests as 'Completed' 
@app.route("/api/update_request_status/<int:request_id>", methods=["PUT"])
def update_request_status(request_id):
    data = request.get_json()
    new_status = data.get("status")

    # Fetch the service request by ID
    service_request = ServiceRequest.query.get(request_id)
    if not service_request:
        return jsonify({"error": "Service request not found"}), 404

    if service_request.status == "Accepted":
        service_request.status = "Completed"
        service_request.date_of_completion = datetime.utcnow()  # Set completion date
        db.session.commit()
        return jsonify({"message": "Request marked as completed successfully"})

    return jsonify({"error": "Invalid status update"}), 400










#not in use
@app.route('/api/service-request', methods=['POST'])
@cross_origin(origins="http://localhost:8080")
def create_service_request():
    data = request.json
    service_id = data.get('service_id')
    customer_id = data.get('customer_id')
    if not service_id or not customer_id:
        return jsonify({"error": "Missing required fields"}), 400
    new_request = ServiceRequest(
        service_id=service_id,
        customer_id=customer_id
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({"message": "Service request created successfully!", "request_id": new_request.id}), 201



@app.route('/service-provider/requests', methods=['GET'])
def get_service_requests():
    # Get the logged-in service provider
    current_provider = ServiceProvider.query.filter_by(email=get_jwt_identity()).first()
    if not current_provider:
        return jsonify({"error": "Unauthorized"}), 403

    # Find all service requests where the service_name matches
    matching_requests = (
        db.session.query(ServiceRequest)
        .join(Service, ServiceRequest.service_id == Service.id)
        .filter(Service.service_name == current_provider.service_name)
        .all()
    )

    # Serialize response
    requests_data = [
        {
            "id": req.id,
            "customer_id": req.customer_id,
            "service_id": req.service_id,
            "status": req.status,
            "date_of_request": req.date_of_request.strftime("%Y-%m-%d %H:%M:%S"),
            "date_of_completion": req.date_of_completion.strftime("%Y-%m-%d %H:%M:%S") if req.date_of_completion else None,
        }
        for req in matching_requests
    ]
    return jsonify(requests_data)



if __name__ == '__main__':
    app.run()