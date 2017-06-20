#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import random
import hashlib
import hmac
import string

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)

secret = 'du.uyX9fE~Tb6.pp&U3D-OsmYO,Gqi$^jS34tzu9'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        if self.user:
            params['user'] = self.user.name
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-cookie', '%s=%s Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-cookie',
                                         'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.title + '</b><br>')
    response.out.write(post.content)


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# create a user class inherited from model class of db

class User(db.Model):

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(
        cls,
        name,
        pw,
        email=None,
                    ):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# creats Post fucntion for database storage

class Post(db.Model):

    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now_add=True)
    u_id = db.StringProperty(required=True)
    likes = db.ListProperty(int, default=None)

    def render(self, u_id=None):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self, u_id=u_id)


class BlogFront(BlogHandler):

    def get(self):
        post = Post.all().order('-created')
        uid = self.read_secure_cookie('u_id')

        # posts = db.GqlQuery("select * from Post order by created desc")

        self.render('front.html', posts=post, uid=uid)


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')

        if not post:
            self.error(404)
            return
        self.render('postBase.html', post=post, u_id=uid)


class LikePage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)
        if not p:
            return self.redirect('login')

        uid = self.read_secure_cookie('user_id')

        if p.u_id != uid:

            if int(uid) in p.likes:
                p.likes.remove(int(uid))
                p.put()
                self.redirect('/post/%s' % str(p.key().id()))
            else:

                p.likes.append(int(uid))
                p.put()
                self.redirect('/post/%s' % str(p.key().id()))
        else:

            self.redirect('/post/%s?error=notOwn' % str(p.key().id()))


class NewPost(BlogHandler):

    def get(self):
        uid = self.read_secure_cookie('user_id')
        if not self.user:
            return self.redirect('/login')
        self.render('newpost.html')

    def post(self):
        uid = self.read_secure_cookie('user_id')
        if not self.user:
            return self.redirect('/login')
        title = self.request.get('title')
        content = self.request.get('content')
        if title and content:
            p = Post(parent=blog_key(), title=title, content=content,
                     u_id=uid)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = 'title and content are nessecary!'
            self.render('newpost.html', title=title, content=content,
                        error=error, u_id=uid)


class DeletePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.redirect('/')
            return

        uid = self.read_secure_cookie('user_id')

        if post.u_id != uid:
            err = 'Permission Denied'
            self.render('delete.html', err=err)
        else:

            err = ''
            db.delete(key)
            self.render('delete.html', err=err)


class EditPost(BlogHandler):

    def get(self, p_id):
        key = db.Key.from_path('Post', int(p_id), parent=blog_key())
        p = db.get(key)

        if not p:
            self.redirect('/post/%s' % str(p.key().id()))

        uid = self.read_secure_cookie('user_id')

        if p.u_id != uid:
            err = 'Permission Denied'
        else:

            err = ''
        self.render('edit.html', post=p, err=err, uid=uid)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)
        if not p:
            return self.redirect('login')

        uid = self.read_secure_cookie('user_id')
        title = self.request.get('title')
        content = self.request.get('content')

        if title and content and p.u_id == uid:
            p.title = title
            p.content = content
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            err = 'Fill in the title and content!'
            self.render('edit.html', post=p, err=err)


# Username , Password and email verifictation

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_user(username):
    return username and USER_RE.match(username)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_mail(email):
    return email and EMAIL_RE.match(email)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_pwd(password):
    return password and PASS_RE.match(password)


class Signup(BlogHandler):

    def get(self):
        self.render('register.html')

    def post(self):
        have_err = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.email = self.request.get('email')
        self.verify = self.request.get('vpassword')

        param = dict(username=self.username, email=self.email)

        if not valid_user(self.username):
            param['error_username'] = "That's not a valid username."
            have_err = True

        if not valid_pwd(self.password):
            param['error_password'] = "That's not a valid password"
            have_err = True
        elif self.password != self.verify:

            param['error_verify'] = 'Your password didnt matched'
            have_err = True

        if not valid_mail(self.email):
            param['error_email'] = 'Thats not a valid mail'
            have_err = True

        if have_err:
            self.render('register.html', **param)
        else:

            # self.redirect('/unit2/welcome?username=' + self.username)

            self.done()

            def done(self, *a, **kw):
                raise NotImplementedError


# Register new users for blog

class Register(Signup):

    def done(self):

        # check if the user already

        u = User.by_name(self.username)

        # username = self.request.get('username')

        if u:
            msg = 'That user already exists.'
            self.render('register.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.render('front.html', username=self.username)
            # self.redirect('/')


class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        post = Post.all().order('-created')
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)

            # self.render('front.html', username = username, post = post)

            self.redirect('/')
        else:

            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/', BlogFront),
    ('/post/([0-9]+)', PostPage),
    ('/delete/([0-9]+)', DeletePost),
    ('/edit/([0-9]+)', EditPost),
    ('/like/([0-9]+)', LikePage),
    ('/newpost', NewPost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)
