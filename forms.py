from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    login = SubmitField("Login")


class SignupForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    reenter_password = PasswordField("Re-enter password", validators=[DataRequired()])
    consent = BooleanField("Consent")
    signup = SubmitField("Signup")


class CreatePartyForm(FlaskForm):
    party_name = StringField("Party name", validators=[DataRequired()])
    max_members = IntegerField("Maximum number of members", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    time = StringField("Time", validators=[DataRequired()])
    create = SubmitField("Create party")


class EditPartyForm(FlaskForm):
    party_name = StringField("Party name", validators=[DataRequired()])
    max_members = IntegerField("Maximum number of members", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    time = StringField("Time", validators=[DataRequired()])
    edit = SubmitField("Edit party")
