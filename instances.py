import datetime, boto.ec2, urllib, cgi, logging, hashlib, os, re, captcha

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.api import urlfetch
from google.appengine.api import mail
from google.appengine.ext.webapp import template

from django.core.validators import email_re
from settings import *

class InstanceUser(db.Model):
    first_name = db.StringProperty()
    last_name = db.StringProperty()
    company = db.StringProperty()
    phone = db.StringProperty()
    email = db.StringProperty()
    token = db.StringProperty()
    reservation = db.StringProperty()
    
EMAIL = """
Dear %(first_name)s:

Your Acunu trial instances are being generated.  Please visit %(domain_name)s/instances?mode=status&token=%(token)s for the login credentials.

Please contact Acunu <contact@acunu.com> with any questions.

Thanks

Acunu
"""

class InstancesPage(webapp.RequestHandler):

    def show_index(self, params={}, c_error=None):
        path = os.path.join(os.path.dirname(__file__), 'templates/index.html')

        params['chtml'] = captcha.displayhtml(
          public_key = RECAPTCHA_PUBLIC,
          use_ssl = False,
          error = c_error)
          
        self.response.out.write(template.render(path, params))

    def message(self, message):
        path = os.path.join(os.path.dirname(__file__), 'templates/message.html')
        self.response.out.write(template.render(path, {'message': message}))

    def initial_request(self):
        
        first_name = cgi.escape(self.request.get('first-name'))
        last_name = cgi.escape(self.request.get('last-name'))
        phone = cgi.escape(self.request.get('phone'))
        company = cgi.escape(self.request.get('company'))
        email = cgi.escape(self.request.get('email'))
        challenge = cgi.escape(self.request.get('recaptcha_challenge_field'))
        response  = cgi.escape(self.request.get('recaptcha_response_field'))
        remoteip  = os.environ['REMOTE_ADDR']
        
        params={
            "first_name": first_name,
            "last_name": last_name,
            "phone": phone,
            "company": company,
            "email": email,
        }
        
        # Do a bunch of form verification
        
        cResponse = captcha.submit(challenge, response, RECAPTCHA_PRIVATE, remoteip)

        error = False

        if len(first_name) > 100 or " " in first_name:
            params["name_error"] = "Invalid name."
            error = True

        if not re.match(email_re, email):
            params["email_error"] = "That email address is not valid.  Nice try Adrien!"
            error = True
            
        # check user doesn't already have a request
        users = db.GqlQuery("SELECT * FROM InstanceUser WHERE email = :email", email=email)
        if users.count() > 0:
            params["email_error"] = "That email address has already been used.  Sorry!"
            error = True

        if not cResponse.is_valid:
            self.show_index(c_error=cResponse.error_code, params=params)
            return
            
        if error:
            self.show_index(params=params)
            return
        
        # Now bung a record in out datastore for later perusal, after we 
        # confirm email if accurate

        token = hashlib.sha1('%s$%s' % (email, SALT)).hexdigest()
        
        # Store email, token
        user = InstanceUser(first_name=first_name, last_name=last_name,
            company=company, phone=phone, email=email, token=token);
        user.put()
        
        # Send email
        mail.send_mail(sender="Acunu.com Downloads <tom@acunu.com>",
                      to=email,
                      subject="Your Acunu trial instance",
                      body= EMAIL % {"first_name": first_name, "token": token, "domain_name": self.request.host_url})

        self.message("Please check your email for further instructions")

    def launch(self, conn, user):
        # Run a few instances
        reservation = conn.run_instances(image_id=AMI_ID, min_count=INSTANCES, max_count=INSTANCES,
            key_name="public-key", security_groups=["public-group"], instance_type="m1.large")
            
        user.reservation = reservation.id
        user.put()
        
    def status(self):
        token = cgi.escape(self.request.get('token'))
        
        # check user doesn't already have a request
        users = db.GqlQuery("SELECT * FROM InstanceUser WHERE token = :token", token=token)
        if users.count() == 0:
            self.message("Invalid token - nice try!")
            return

        user = users[0]
        
        conn = boto.ec2.connect_to_region(REGION,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY)
        
        # if user doesn't have a reservation, then launch some instances
        if user.reservation is None:
            self.launch(conn, user)
        
        # Get the reservation object
        params = {"Filter.0.Name": "reservation-id", "Filter.0.Value.0" : user.reservation}
        reservations = conn.get_list('DescribeInstances', params,
                             [('item', boto.ec2.instance.Reservation)], verb='POST')
        
        if len(reservations) == 0:
            self.message("Something went wrong - not your fault!  Tell Tom.")
            return
        
        reservation = reservations[0]
        pending = []
        running = []
        
        for instance in reservation.instances:
            instance.update()
            
            if instance.state != "running":
                pending.append({'id': instance.id, 'state': instance.state })
            else:
                running.append({'id': instance.id, 'address': instance.public_dns_name })

        path = os.path.join(os.path.dirname(__file__), 'templates/status.html')
        self.response.out.write(template.render(path, {'pending': pending, 'running': running}))
    
    def get(self):
        mode = cgi.escape(self.request.get('mode'))
                
        if mode == "request":
            self.initial_request()
        elif mode == "status":
            self.status()
        else:
            self.show_index()
            
    def post(self):
        self.get()

application = webapp.WSGIApplication([ 
        ('/instances', InstancesPage),
    ], debug=True)

def main():
    logging.getLogger().setLevel(logging.DEBUG)
    run_wsgi_app(application)

if __name__ == "__main__":
    main()