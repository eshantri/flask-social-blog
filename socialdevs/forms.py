from flask.app import Flask
import email_validator
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from socialdevs.models import User


class registrationForm(FlaskForm):
    username = StringField("Username",
                           validators=[DataRequired(),
                                       Length(min=5, max=30)])
    email = StringField(
        "Email",
        validators=[DataRequired(),
                    Email("Please Enter a valid Email")])
    password = PasswordField("Password", validators=[DataRequired()])
    confirmPassword = PasswordField(
        'Confirm Password', validators=[DataRequired(),
                                        EqualTo('password')])
    submit = SubmitField('Sign Up!')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email is taken. Please choose a different one.')


class loginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(0)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember")
    submit = SubmitField('Log In')


class updateForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(),
                                       Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture',
                        validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(
                    'That email is taken. Please choose a different one.')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Title', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EmailConfirmationForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(),
                    Email("Please Enter a valid Email")])
    confirm_email = StringField("Email",
                                validators=[DataRequired(),
                                            EqualTo('email')])
    submit = SubmitField('Submit')

    # def validate_email(self, email):
    #     try:
    #         user = User.query.filter_by(email=email.data).first()
    #         print(user)
    #     except AttributeError:
    #             raise ValidationError(
    #                 'That email is invalid. Please enter a valid email or create a new account.'
    # )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if not user:
            raise ValidationError(
                'That email is invalid. Please enter a valid email or create a new account.'
            )


class PasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(),
                                        EqualTo('password')])
    submit = SubmitField('Submit')