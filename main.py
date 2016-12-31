import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random

from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'secret' # :P

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(password, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(password + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(password, salt)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        val = self.request.cookies.get(name)
        return val and check_secure_val(val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_active_user(self):
        user_id = self.read_secure_cookie('user_id')
        if user_id:
            user = Users.get_by_id(int(user_id))
            return user

class Users(db.Model):
    username = db.StringProperty(required = True)
    passhash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def register(cls, username, password, email=None):
        passhash = make_pw_hash(password)
        return Users(username=username,
                     passhash=passhash,
                     email = email)

    @classmethod
    def get_user_by_name(cls, username):
        a = db.GqlQuery("select * from Users where username=:1", username)
        return a

    @classmethod
    def login(cls, name, pw):
        a = cls.by_name(name)
        if a and valid_pw(name, pw, a.passhash):
            return a

class Signup(Handler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def get(self):
        user = self.get_active_user()
        if user:
            self.render("base.html",
                        user=user,
                        message="""You are already signed in!  <a href='/logout'>Log out<a>
                                   before creating a new account or return to the
                                   <a href='/'>front page</a>""")
        else:
            self.render("signup.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        name_err, pass_err, match_err, email_err = "","","",""

        if not self.USER_RE.match(username):
            name_err = "That wasn't a valid username"
        if not self.PASS_RE.match(password):
            pass_err = "That wasn't a valid password"
        if (not pass_err) and password != verify:
            match_err = "Passwords didn't match"
        if email and (not self.MAIL_RE.match(email)):
            email_err = "That wasn't a valid email"

        if name_err or pass_err or match_err or email_err:
            self.render("signup.html",
                         username  = username,
                         email     = email,
                         name_err  = name_err,
                         pass_err  = pass_err,
                         match_err = match_err,
                         email_err = email_err)
        else:
            a = Users.get_user_by_name(username).get()
            if a:
                self.render("signup.html", name_err = "That username already exists")
            else:
                b = Users.register(username, password, email)
                b.put()
                self.login(b)
                self.redirect('/')

class Login(Handler):
    def get(self):
        user = self.get_active_user()
        if not user:
            self.render("login.html")
        else:
            self.render("base.html",
                        user=user,
                        message="""You are already signed in!  <a href='/logout'>Log out<a>
                                   before signing in a new account or return to the
                                   <a href='/'>front page</a>.""")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        a = Users.get_user_by_name(username).get()
        if a:
            if valid_pw(password, a.passhash):
                self.login(a)
                self.redirect('/')
            else:
                self.render("login.html", pass_err="Incorrect password")
        else:
            self.render("login.html", name_err="Username didn't exist in database")

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Posts(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    submitter_id = db.IntegerProperty(required = True)
    created = db.DateProperty(auto_now_add = True)

class NewPost(Handler):
    def render_newpage(self, user, subject = "", post = "", error = ""):
        self.render("new_post.html", subject=subject, post=post, error=error, user=user)

    def get(self):
        user = self.get_active_user()
        if user:
            self.render_newpage(user=user)
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        post = self.request.get('post')
        created_by = int(self.get_active_user().key().id())

        if subject and post:
            a = Posts(subject=subject, content=post, submitter_id=created_by)
            a.put()
            self.redirect('/%s' % str(a.key().id()))
        else:
            self.render_newpage(subject, post, error="Please provide both a subject and a post!")

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Posts', int(post_id))
        post = db.get(key)
        user = self.get_active_user()

        if not post:
            self.error(404)
            return
        if not user:
            self.redirect('/login')
        self.render("permalink.html", post=post, user=user)

class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Posts order by created desc limit 10")
        user = self.get_active_user()
        self.render("main.html", posts=posts, user=user)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', PostPage),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout)
                              ],
                              debug = True)
