from flask.globals import request
from socialdevs import app, db, bcrypt
from flask import Flask, url_for, redirect, request, abort
from flask.helpers import flash
from socialdevs import bcrypt
from flask.templating import render_template
from socialdevs.models import User, Post
from socialdevs.forms import EmailConfirmationForm, PasswordForm, registrationForm, loginForm, updateForm, PostForm
from flask_login import login_user, current_user, logout_user, login_required
import os
import secrets
from PIL import Image
from socialdevs.tokens import generate_confirmation_token, confirm_token
from socialdevs.sendEmail import send_email


@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page,
                                                                  per_page=5)
    return render_template('home.html', posts=posts)


@app.route('/register', methods=['GET', "POST"])
def register():
    if current_user.is_authenticated:

        return redirect(url_for('home'))
    form = registrationForm()
    if (form.validate_on_submit()):
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        username = form.username.data
        email = form.email.data
        user = User(password=hashed_password, username=username, email=email)
        db.session.add(user)
        db.session.commit()

        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title='Register')


@app.route('/login', methods=['GET', "POST"])
def login():
    if current_user.is_authenticated:

        return redirect(url_for('home'))
    form = loginForm()
    if (form.validate_on_submit()):
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,
                                               form.password.data):
            login_user(user)
            flash('You have logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(
                url_for('home'))
        else:
            flash('Please enter valid credentials!', 'danger')
    return render_template('login.html', form=form, title='Login')


@app.route("/logout")
def logout():
    logout_user()
    flash("You've been logged out", 'success')
    return redirect(url_for('home'))


@app.route('/about')
def about():
    return render_template('about.html')


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static', 'profile', picture_fn)
    if current_user.profile != 'default.jpg':
        prev_picture = os.path.join(app.root_path, 'static', 'profile',
                                    current_user.profile)
        if os.path.exists(prev_picture):
            os.remove(prev_picture)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    image_file = url_for('static', filename='profile/' + current_user.profile)

    form = updateForm()
    if form.validate_on_submit():
        # print(form.picture.data)
        if form.picture.data:
            picture_file = save_picture(form.picture.data)

            current_user.profile = picture_file

        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated', 'success')
        return redirect(url_for('account'))
    return render_template('account.html',
                           title='Account',
                           image_file=image_file,
                           form=form)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data,
                    content=form.content.data,
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html',
                           title='Create Post',
                           legend="New Post",
                           form=form)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated', 'success')
        return redirect(url_for('post', post_id=post_id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html',
                           title='Update Post',
                           legend="Update Post",
                           form=form)


@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)

    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted', 'success')
    return redirect(url_for('home'))


@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)


@app.route("/forgot_password", methods=['GET', 'POST'])
def reset_password_page():
    form = EmailConfirmationForm()
    if form.validate_on_submit():
        token = generate_confirmation_token(form.email.data)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('resetlink.html', confirm_url=confirm_url)
        subject = "Please click this link to reset your password"
        print(form.email.data)
        send_email(form.email.data, subject, html)
        flash('Please check your email for next steps!', 'info')
        return redirect(url_for('login'))
    return render_template('forgotpass.html',
                           title='Reset Your password',
                           form=form)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password(token, user):
    form = PasswordForm()
    return render_template('resetpass.html',
                           title='Reset Your password',
                           form=form)


@app.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    email = ""
    try:
        email = confirm_token(token)
        user = User.query.filter_by(email=email).first_or_404()
        form = PasswordForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('The password has been reset!', 'success')
            return redirect(url_for('login'))
        return render_template('resetpass.html',
                               title='Reset Your password',
                               form=form)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')

    return redirect(url_for('login'))