from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, InputRequired

class LoginForm(FlaskForm):
    auth_method = SelectField('Authentication Method', choices=[('local', 'Local'), ('ldap', 'LDAP')], validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class EmailChangeForm(FlaskForm):
    email = StringField("New Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Change Email")


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[InputRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[InputRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')
