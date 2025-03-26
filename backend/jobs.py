from celery import Task
from flask_mail import Message
from mailing import mail
from app import celery_app, create_app
from models import db, test, user_datastore, Role, User, roles_users, test2, ServiceProvider, Service, ServiceRequest, PendingServiceRequest, Flag
from celery_context import flask_context
from flask import render_template_string 


app = create_app()  # Create a new Flask instance


'''
@celery_app.task(base=flask_context)
def celery_hello():
    print('Hello, Celery!')
    from time import sleep
    sleep(5)
    cate = Service.query.first()
    return cate.service_name
'''

@celery_app.task(base=flask_context)
def send_mail_task():
    print("Sending email...")

    # Ensure the task runs inside Flask's application context
    with app.app_context():
        services = Service.query.all()

        # Create an HTML table with service details
        html_table = """
        <h2>Monthly Service Report</h2>
        <table border="1" cellspacing="0" cellpadding="5">
            <tr>
                <th>ID</th>
                <th>Service Name</th>
                <th>Description</th>
                <th>Base Price</th>
                <th>Status</th>
            </tr>
            {% for service in services %}
            <tr>
                <td>{{ service.id }}</td>
                <td>{{ service.service_name }}</td>
                <td>{{ service.description }}</td>
                <td>${{ service.base_price }}</td>
                <td>{{ service.status }}</td>
            </tr>
            {% endfor %}
        </table>
        """

        # Render HTML with data
        email_body = render_template_string(html_table, services=services)

        # Create email message
        msg = Message(
            subject="Monthly Service Report",
            sender="no-reply@example.com",  # Set a valid sender
            recipients=["to@example.com"],  # Use MailHog or your email
            html=email_body,  # Attach the HTML table
        )
        
        mail.send(msg)  # Send the email
        print("Service report email sent successfully!")

    return "Service report sent"


@celery_app.task(base=flask_context)
def send_pending_requests_email():
    print("Sending pending service request emails...")

    with app.app_context():
        # Fetch pending service requests
        pending_requests = ServiceRequest.query.filter_by(status="Requested").all()

        if not pending_requests:
            print("No pending requests found.")
            return "No pending requests."

        # Extract unique customer IDs
        customer_ids = list(set(req.customer_id for req in pending_requests))

        # Fetch customer details
        customers = {user.id: user.email for user in User.query.filter(User.id.in_(customer_ids)).all()}

        # Group pending requests by customer
        pending_by_customer = {}
        for req in pending_requests:
            pending_by_customer.setdefault(req.customer_id, []).append(req)

        # Send email to each customer with their pending requests
        for customer_id, requests in pending_by_customer.items():
            customer_email = customers.get(customer_id)
            if not customer_email:
                print(f"Skipping customer ID {customer_id}, email not found.")
                continue
            
            # Create email body
            html_table = """
            <h2>⚠️ Pending Service Requests</h2>
            <p>Hello,</p>
            <p>You have pending service requests. Please check and take action.</p>
            <table style="width:100%; border-collapse:collapse; font-family:Arial, sans-serif;">
                <thead>
                    <tr style="background-color:#343a40; color:white;">
                        <th style="padding:10px; border:1px solid #ddd;">Request ID</th>
                        <th style="padding:10px; border:1px solid #ddd;">Service Name</th>
                        <th style="padding:10px; border:1px solid #ddd;">Request Date</th>
                        <th style="padding:10px; border:1px solid #ddd;">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for req in requests %}
                    <tr style="background-color:{% if loop.index is even %}#f8f9fa{% else %}#ffffff{% endif %};">
                        <td style="padding:10px; border:1px solid #ddd;">{{ req.id }}</td>
                        <td style="padding:10px; border:1px solid #ddd;">{{ req.service.service_name }}</td>
                        <td style="padding:10px; border:1px solid #ddd;">{{ req.date_of_request }}</td>
                        <td style="padding:10px; border:1px solid #ddd; color:#dc3545;"><strong>{{ req.status }}</strong></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p>Thank you,<br>Service Team</p>
            """

            # Render the HTML email body
            email_body = render_template_string(html_table, requests=requests)

            # Create and send email
            msg = Message(
                subject="⚠️ Action Required: Pending Service Requests",
                sender="household@services.com",
                recipients=[customer_email],
                html=email_body
            )
            
            mail.send(msg)
            print(f"Pending request email sent to {customer_email}")

    return "Pending request emails sent successfully!"
