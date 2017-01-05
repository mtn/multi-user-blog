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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'secret'  # :P


def make_salt(length=5):
    """Makes salt for secure authentication"""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(password, salt=None):
    """Creates password,password hash tuple"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(password+salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(password, h):
    """Validates password with hash"""
    salt = h.split(',')[0]
    return h == make_pw_hash(password, salt)


def make_secure_val(val):
    """Creates a secure value"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """Checks if a secure value is correct"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    """Convenience functions inherited by many classes"""
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
                    message="""It looks like you've accessed the %s post
                               endpoint improperly; redirecting to the home
                               page. <a href='/'>Click here</a> to go
                               immediately.""" % endpoint)


class Users(db.Model):
    """
    User model. Username and hashed password, plus optional email recorded
    for each user.
    """
    username = db.StringProperty(required=True)
    passhash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def register(cls, username, password, email=None):
        """
        Registers user, passing username and email plus hashed password
        to constructor
        """
        passhash = make_pw_hash(password)
        return Users(username=username,
                     passhash=passhash,
                     email=email)

    @classmethod
    def get_user_by_name(cls, username):
        """
        Convenience query of username. Because usernames are unique, at
        most a single return is guaranteed
        """
        a = db.GqlQuery("select * from Users where username=:1", username)
        return a

    @classmethod
    def login(cls, name, pw):
        """
        Verifies existence of user via by-name search and correctness of
        password against passhash
        """
        a = cls.by_name(name)
        if a and valid_pw(name, pw, a.passhash):
            return a


class Signup(Handler):
    """Handles /signup endpoint"""
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    MAIN_HEADING = "Sign Up"

    def get(self):
        """
        Handles page query. If user is already signed in, displays message
        and redirects to the front page within 8 seconds. Otherwise, renders
        the signup form.
        """
        user = self.get_active_user()
        if user:
            self.render("redirect_in_8.html",
                        message="""You are already signed in!
                                   <a href='/logout'>Log out<a>
                                   before creating a new account or return to
                                   the <a href='/'>front page</a>""")
        else:
            self.render("signup.html", main_heading=self.MAIN_HEADING)

    def post(self):
        """
        Receieves data when the user signs up, checks to errors. If any exist
        the signup page is rerendered (with some data preserved in text
        fields). Otherwise, the user is created, logged in, and redirected
        to the front page.
        """
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        name_err, pass_err, match_err, email_err = "", "", "", ""

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
                        username=username,
                        email=email,
                        name_err=name_err,
                        pass_err=pass_err,
                        match_err=match_err,
                        email_err=email_err)
        else:
            a = Users.get_user_by_name(username).get()
            if a:
                self.render("signup.html",
                            name_err="That username already exists",
                            main_heading=self.MAIN_HEADING)
            else:
                b = Users.register(username, password, email)
                b.put()
                self.login(b)
                self.redirect('/')


class Login(Handler):
    """Handles /login endpoint"""
    LOGIN_FORM = True
    MAIN_HEADING = "Login"

    def get(self):
        """
        Checks if a user is already signed in. If none is, login form is
        rendered. If one is, they are shown a message and redirected to
        the front page after 8 seconds.
        """
        user = self.get_active_user()
        if not user:
            self.render("login_signupbase.html",
                        login=self.LOGIN_FORM,
                        main_heading=self.MAIN_HEADING)
        else:
            self.render("redirect_in_8.html",
                        message="""You are already signed in! <a href='/logout'>
                                   Log out</a> before signing in with a new
                                   account or return to the
                                   <a href='/'>front page</a>.""")

    def post(self):
        """
        Handles data returned by login form. Uses previously defined funecions
        to verify proper input and creates the user. Rerenders form with
        errrors (incorrect password, non-existant user) as necessary.
        """
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
    """Handles /logout endpoint"""
    def get(self):
        """Logs user our and redirects to front page"""
        self.logout()
        self.redirect('/')


class Posts(db.Model):
    """Posts datastore model"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    submitter_id = db.IntegerProperty(required=True)
    created = db.DateProperty(auto_now_add=True)
    liked_by = db.ListProperty(int, indexed=False, default=[], required=True)


class NewPost(Handler):
    """
    Handles post creation and also post editing (routed through this
    endpoint for convenience
    """
    MAIN_HEADING = "New Post"

    def render_newpage(self, user, subject="", post_content="", error=""):
        """Convenience function to render post creation/modification page"""
        self.render("mod_post_base.html",
                    subject=subject,
                    post_content=post_content,
                    error=error,
                    user=user,
                    main_heading=self.MAIN_HEADING)

    def get(self):
        """
        Renders newpost page if there is a user signed in. If not, redirect
        to login page
        """
        user = self.get_active_user()
        if user:
            self.render_newpage(user=user)
        else:
            self.redirect('/login')

    def post(self):
        """Creates post, or updates existing post if valid post_id provided"""
        subject = self.request.get('subject')
        post_content = self.request.get('post_content')
        submit = self.request.get('submit')
        cancel = self.request.get('cancel')
        user = self.get_active_user()
        created_by = int(user.key().id())
        post_id = self.request.get('post_id')

        if not user:
            self.redirect('/login')
        if post_id:
            post = Posts.get_by_id(int(post_id))
        else:
            post = None

        if cancel == "cancel":
            self.redirect('/%s' % str(post.key().id()))
            return
        if (post and post.submitter_id == user.key().id()) or not post:
            if submit == "submit" and subject and post_content:
                if post:
                    post.subject = subject
                    post.content = post_content
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
                                    error="""Please provide both a subject and a
                                             post!""")
        else:
            self.redirect('/login')


class EditPost(Handler):
    """Handles post edit endpoint"""
    MAIN_HEADING = "Edit Post"

    def render_editpage(self, user, post_id, subject, post_content, error=""):
        """Convenience render function"""
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
        """Abstracted function for redndering improper access messages"""
        self.render_improper_endpoint_access("edit")

    def get(self):
        """Renders improper access message"""
        self.render_improper_access()

    def post(self):
        """Checks provided arguments for consistency and updates post"""
        subject = self.request.get('subject')
        content = self.request.get('post_content')
        post_id = self.request.get('post_id')
        post = Posts.get_by_id(int(post_id))
        user = self.get_active_user()
        user_id = int(user.key().id())

        if post and user and subject and content:
            if post.submitter_id == user_id:
                self.render_editpage(user, post_id, subject, content)
            else:
                self.render_improper_access()
        else:
            self.error(500)


class DeletePost(Handler):
    """Post deletion handler"""
    def post(self):
        """
        Retrieves and deletes post after checking that signed-in user owns it
        """
        post_id = int(self.request.get('post_id'))
        post = Posts.get_by_id(post_id)
        if post.submitter_id == self.get_active_user().key().id():
            post.delete()
        else:
            self.error(403)
        self.redirect('/')


class RenderPost(Handler):
    """Handles post view endpoint"""
    def render_permalink(self, post, comments, edit_id=None, user=None,
                         owns=False):
        """Convenience render function"""
        username = Users.get_by_id(post.submitter_id).username
        self.render("permalink.html",
                    main_heading=post.subject,
                    main_desc="by: " + username,
                    post=post,
                    user=user,
                    comments=comments,
                    num_comments=len([comment for comment in comments]),
                    num_likes=len(post.liked_by),
                    edit_id=edit_id,
                    owns=owns)

    def get(self, post_id):
        """
        Renders post with id matching url and (for convenience) handles
        comment deletion
        """
        key = db.Key.from_path('Posts', int(post_id))
        post = db.get(key)
        user = self.get_active_user()
        edit_id = self.request.get('edit')
        delete_id = self.request.get('delete')

        if not post:
            self.error(404)
            return

        comments = db.GqlQuery("""select * from Comments where
                                  post_id = %s""" % str(post.key().id()))
        if not user:
            self.render_permalink(post=post, comments=comments)
            return
        if delete_id:
            comment = Comments.get_by_id(int(delete_id))
            comment.delete()

        owned_by_user = int(user.key().id()) == post.submitter_id
        likes = int(user.key().id()) in post.liked_by
        self.render_permalink(user=user,
                              post=post,
                              comments=comments,
                              edit_id=edit_id,
                              owns=owned_by_user)


class LikeHandler(Handler):
    """Handles likes"""
    def post(self):
        """Checks if a user has liked a post, assesses changes accordingly"""
        liked = self.request.get('like')
        unliked = self.request.get('unlike')
        post_id = self.request.get('post_id')
        post = Posts.get_by_id(int(post_id))
        user = self.get_active_user()
        user_id = int(user.key().id())

        if liked:
            if user_id in post.liked_by:
                self.render_improper_endpoint_access("like")
            else:
                if post.submitter_id != user_id:
                    post.liked_by.append(user.key().id())
                    post.put()
                    self.redirect('/%s' % str(post.key().id()))
                else:
                    self.error(403)
        elif unliked:
            if user_id in post.liked_by:
                index = post.liked_by.index(user_id)
                del post.liked_by[index]
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                self.error(500)


class Comments(db.Model):
    """Comment model"""
    submitter_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)


class NewComment(Handler):
    """Handles comment creation"""
    def post(self):
        """Creates comment after verifying that a user is signed in"""
        post_id = int(self.request.get('post_id'))
        post = Posts.get_by_id(post_id)
        comment = self.request.get('comment')
        submitter_id = self.get_active_user().key().id()

        if submitter_id:
            comment = Comments(post_id=post_id, content=comment,
                               submitter_id=submitter_id)
            comment.put()
            self.redirect('/%s' % str(post.key().id()))
        else:
            self.error(403)


class ModComment(Handler):
    """Handles comment modification"""
    def post(self):
        """
        Receieves modified comment, performs checks, and updates datastore
        """
        modified_content = self.request.get('comment_edit')
        comment_id = self.request.get('comment_id')
        comment = Comments.get_by_id(int(comment_id))
        user = self.get_active_user()

        if user.key().id() == comment.submitter_id:
            comment.content = modified_content
            comment.put()
            self.redirect('/%s' % str(comment.post_id))
        else:
            self.error(403)


class DeleteComment(Handler):
    """Comment deletion handler"""
    def post(self):
        """Checks that signed in user owns comment before deleting"""
        comment_id = int(self.request.get('comment_id'))
        post_id = self.request.get('post_id')
        comment = Comments.get_by_id(comment_id)
        if comment.submitter_id == self.get_active_user().key().id():
            comment.delete()
        else:
            error(403)

        self.redirect('/%s' % post_id)


class Profile(Handler):
    """Profile rendering"""
    def get(self):
        user_id = self.request.get('user_id')
        if not user_id:
            user_id = str(self.get_active_user().key().id())
        if not user_id:
            self.redirect('/login')
        user_id = int(user_id)
        user = Users.get_by_id(user_id)
        posts = db.GqlQuery("select * from Posts where submitter_id=:1"
                            ,user_id)
        comments = db.GqlQuery("select * from Comments where"
                               " submitter_id=:1",user_id)
        self.render("profile.html",
                    main_heading="User: " + user.username,
                    main_desc="Your posts and comments",
                    user=user,
                    num_comments=len([comment for comment in comments]),
                    num_posts=len([post for post in posts]),
                    posts=posts,
                    comments=comments)


class MainPage(Handler):
    """Renders main page"""
    def get(self):
        main_desc = """A multi-user blog built using jinja2, Google App Engine,
                       and the Clean Blog Theme by Start Bootstrap"""
        main_heading = "Blog"
        user = self.get_active_user()
        show_more = self.request.get('show_more')

        to_show = self.request.get('to_show')
        if not to_show:
            to_show = "10"
        if show_more == "True":
            to_show = str(int(to_show)+10)
        posts = db.GqlQuery("""select * from Posts order by created desc
                               limit %s""" % to_show)

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
                               ('/comment', NewComment),
                               ('/modcomment', ModComment),
                               ('/delete_comment', DeleteComment),
                               ('/delete_post', DeletePost),
                               ('/profile', Profile)
                               ],
                              debug=True)
