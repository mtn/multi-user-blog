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

    def render_improper_endpoint_access(self, endpoint):
        self.render("redirect_in_8.html",
                message="""It looks like you've accessed the %s post endpoint
                           improperly; redirecting to the home page.
                           <a href='/'>Click here</a> to go immediately.""" % endpoint)

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

    MAIN_HEADING = "Sign Up"

    def get(self):
        user = self.get_active_user()
        # TODO handle this
        if user:
            self.render("redirect_in_8.html",
                    message="""You are already signed in!  <a href='/logout'>Log out<a>
                                   before creating a new account or return to the
                                   <a href='/'>front page</a>""")
        else:
            self.render("signup.html", main_heading=self.MAIN_HEADING)

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
                self.render("signup.html",
                             name_err = "That username already exists",
                             main_heading=self.MAIN_HEADING)
            else:
                b = Users.register(username, password, email)
                b.put()
                self.login(b)
                self.redirect('/')

class Login(Handler):
    LOGIN_FORM = True
    MAIN_HEADING = "Login"
    def get(self):
        user = self.get_active_user()
        if not user:
            self.render("login_signupbase.html",
                    login=self.LOGIN_FORM,
                    main_heading=self.MAIN_HEADING)
        else:
            self.render("redirect_in_8.html",
                    message="""You are already signed in!  <a href='/logout'>Log out<a>
                               before signing in with a new account or return to the
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
                self.render("login_signupbase.html",
                        pass_err="Incorrect password",
                        login=self.LOGIN_FORM,
                        main_heading=self.MAIN_HEADING)
        else:
            self.render("login_signupbase.html",
                    name_err="Username didn't exist in database",
                    login=self.LOGIN_FORM,
                    main_heading=self.MAIN_HEADING)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')

class Posts(db.Model):
    subject=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    submitter_id=db.IntegerProperty(required=True)
    created=db.DateProperty(auto_now_add=True)
    liked_by=db.ListProperty(int, indexed=False, default=[], required=True)

class NewPost(Handler):
    MAIN_HEADING="New Post"

    def render_newpage(self, user, subject = "", post_content = "", error = ""):
        self.render("mod_post_base.html",
                subject=subject,
                post_content=post_content,
                error=error,
                user=user,
                main_heading=self.MAIN_HEADING)

    def get(self):
        user = self.get_active_user()
        if user:
            self.render_newpage(user=user)
        else:
            self.redirect('/login')

    def post(self):
        subject=self.request.get('subject')
        post_content=self.request.get('post_content')
        submit=self.request.get('submit')
        cancel=self.request.get('cancel')
        user=self.get_active_user()
        created_by=int(user.key().id())
        post_id=self.request.get('post_id')
        if post_id:
            post=Posts.get_by_id(int(post_id))
        else:
            post=None

        if cancel=="cancel":
            self.redirect('/%s' % str(post.key().id()))
            return
        if submit=="submit" and subject and post_content:
            if post:
                post.subject=subject
                post.content=post_content
                post.put()
            else:
                post = Posts(subject=subject,
                        content=post_content,
                        submitter_id=created_by)
                post.put()
            self.redirect('/%s' % str(post.key().id()))
        else:
            self.render_newpage(user=user,
                    subject=subject,
                    post_content=post_content,
                    error="Please provide both a subject and a post!")

class EditPost(Handler):
    MAIN_HEADING="Edit Post"

    def render_editpage(self, user, post_id, subject, post_content, error = ""):
        self.render("mod_post_base.html",
                subject=subject,
                post_content=post_content,
                error=error,
                user=user,
                post_id=post_id,
                mod1="editing",
                mod2="more",
                main_heading=self.MAIN_HEADING)

    def render_improper_access(self):
        self.render_improper_endpoint_access("edit")

    def get(self):
        self.render_improper_access()

    def post(self):
        subject=self.request.get('subject')
        content=self.request.get('post_content')
        post_id=self.request.get('post_id')
        post=Posts.get_by_id(int(post_id))
        user=self.get_active_user()
        user_id=int(user.key().id())

        if post and user and subject and content:
            if post.submitter_id==user_id:
                self.render_editpage(user,post_id,subject,content)
            else:
                self.render_improper_access()
        else:
            self.error(500)

class RenderPost(Handler):
    def render_permalink(self,post,comments,user=None,owns=False):
        self.render("permalink.html",
                main_heading=post.subject,
                main_desc="by: " + (Users.get_by_id(post.submitter_id)).username,
                post=post,
                user=user,
                comments=comments,
                num_comments=len([comment for comment in comments]),
                num_likes=len(post.liked_by),
                owns=owns)

    def get(self, post_id):
        key = db.Key.from_path('Posts', int(post_id))
        post = db.get(key)
        user = self.get_active_user()

        if not post:
            self.error(404)
            return

        comments = db.GqlQuery("select * from Comments where post_id = %s" % str(post.key().id()))
        if not user:
            self.render_permalink(post=post,comments=comments)
            return


        owned_by_user = int(user.key().id()) == post.submitter_id
        likes = int(user.key().id()) in post.liked_by
        self.render_permalink(user=user,
                post=post,
                comments=comments,
                owns=owned_by_user)

class LikeHandler(Handler):
    def post(self):
        liked=self.request.get('like')
        unliked=self.request.get('unlike')
        post_id=self.request.get('post_id')
        post=Posts.get_by_id(int(post_id))
        user=self.get_active_user()
        user_id=int(user.key().id())

        if liked:
            if user_id in post.liked_by:
                self.render_improper_endpoint_access("like")
            else:
                post.liked_by.append(user.key().id())
                post.put()
                self.redirect('/%s' % str(post.key().id()))
        elif unliked:
            if user_id in post.liked_by:
                index=post.liked_by.index(user_id)
                del post.liked_by[index]
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                self.error(500)

class Comments(db.Model):
    submitter_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required = True)

class NewCommentHandler(Handler):

    #TODO handle deletion and edits
    def post(self):
        post_id=int(self.request.get('post_id'))
        post=Posts.get_by_id(post_id)
        comment=self.request.get('comment')
        submitter_id=self.get_active_user().key().id()

        comment = Comments(post_id=post_id,content=comment,submitter_id=submitter_id)
        comment.put()
        self.redirect('/%s' % str(post.key().id()))

class MainPage(Handler):
    def get(self):
        main_desc="""A multi-user blog built using jinja2, Google App Engine,
                     and the Clean Blog Theme by Start Bootstrap"""
        main_heading = "Blog"
        user=self.get_active_user()
        show_more=self.request.get('show_more')

        to_show=self.request.get('to_show')
        if not to_show:
            to_show="10"
        if show_more=="True":
            to_show=str(int(to_show)+10)
        posts = db.GqlQuery("select * from Posts order by created desc limit %s" % to_show)

        self.render("main.html",
                posts=posts,
                user=user,
                main_desc=main_desc,
                to_show=to_show,
                main_heading=main_heading)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', RenderPost),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/editpost', EditPost),
                               ('/like', LikeHandler),
                               ('/comment', NewCommentHandler)
                              ],
                              debug = True)
