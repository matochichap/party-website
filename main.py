import sqlite3
import os
from forms import LoginForm, SignupForm, CreatePartyForm, EditPartyForm
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, declarative_base
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

MAX_ALLOWED_MEMBERS = 50

app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///table.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = sqlite3.connect("table.db")  # to create table.db file
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.filter_by(id=user_id).first()


# wrapper to check if logged in
def login_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Not logged in, please login")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# tables
# Documentation: https://docs.sqlalchemy.org/en/14/orm/basic_relationships.html
class Users(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    consent = db.Column(db.Boolean, nullable=False)
    # one-to-many relationship(user creates multiple parties) (bidirectional)
    parties_created = relationship("Parties", back_populates="creator")


class Parties(db.Model, Base):
    __tablename__ = "parties"
    id = db.Column(db.Integer, primary_key=True)
    party_name = db.Column(db.String(100), unique=True, nullable=False)
    max_members = db.Column(db.Integer, nullable=False)
    current_members = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    time = db.Column(db.String(100), nullable=False)
    # one-to-many relationship(user creates multiple parties) (bidirectional)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    creator = relationship("Users", back_populates="parties_created")


class PartyMembers(db.Model, Base):
    __tablename__ = "party_members"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    party_id = db.Column(db.Integer, db.ForeignKey('parties.id'), nullable=False)


db.create_all()


@app.route('/', methods=["GET", "POST"])
def login():
    logout_user()  # ensure no user is logged in
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        selected_user = Users.query.filter_by(email=email).first()
        # if email does not exist
        if selected_user is None:
            flash("Email does not exist. Please try again.")
            return redirect(url_for("login"))
        # if wrong password
        elif not check_password_hash(selected_user.password, password):
            flash("Incorrect password. Please try again.")
            return redirect(url_for("login"))
        # if email and password correct
        else:
            login_user(selected_user)
            return redirect(url_for("parties"))
    return render_template("index.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/signup', methods=["GET", "POST"])
def signup():
    logout_user()  # ensure no user is logged in
    form = SignupForm()
    if form.validate_on_submit():
        # check if passwords match
        if form.password.data == form.reenter_password.data:
            find_email = Users.query.filter_by(email=form.email.data).first()
            # check if email is unique
            if find_email is None:
                hashed_password = generate_password_hash(password=form.password.data, method="pbkdf2:sha256",
                                                         salt_length=8)
                new_user = Users(
                    name=form.name.data,
                    email=form.email.data,
                    password=hashed_password,
                    consent=form.consent.data
                )
                db.session.add(new_user)
                db.session.commit()
                flash("Account created, please login")
                return redirect(url_for("login"))
            else:
                flash("This email is already in use!")
                # return redirect(url_for("signup"))
        else:
            flash("Password mismatch!")
            return redirect(url_for("signup"))
    return render_template("signup.html", form=form)


@app.route('/parties')
@login_only
def parties():
    get_all_parties = Parties.query.all()
    all_parties = []
    # process data
    for party in get_all_parties:
        users = PartyMembers.query.filter_by(party_id=party.id).all()
        members = []
        for user in users:
            member = Users.query.filter_by(id=user.user_id).first()
            member = {"member_id": member.id,
                      "name": member.name,
                      "email": member.email}
            members.append(member)
        new_party = {"id": party.id,
                     "party_name": party.party_name,
                     "max_members": party.max_members,
                     "current_members": party.current_members,
                     "location": party.location,
                     "time": party.time,
                     "creator_id": party.creator_id,
                     "members": members}
        all_parties.append(new_party)

    return render_template("parties.html", user=current_user, all_parties=all_parties)


@app.route('/parties/create-party', methods=["GET", "POST"])
@login_only
def create_party():
    form = CreatePartyForm()
    if form.validate_on_submit():
        find_party = Parties.query.filter_by(party_name=form.party_name.data).first()
        # check if party name is unique
        if find_party is None:
            party_name = form.party_name.data
            max_members = form.max_members.data
            # check if max members is declared in allowable range
            if 1 <= max_members <= MAX_ALLOWED_MEMBERS:
                new_party = Parties(
                    creator=current_user,
                    party_name=party_name,
                    current_members=1,
                    max_members=max_members,
                    location=form.location.data,
                    time=form.time.data
                )
                db.session.add(new_party)
                db.session.commit()
                # commit first to get party id
                # not ideal, but not sure how to get party id without adding into Parties table first
                party_id = Parties.query.filter_by(party_name=party_name).first().id
                new_party_members = PartyMembers(
                    user_id=current_user.id,
                    party_id=party_id
                )
                db.session.add(new_party_members)
                db.session.commit()
                return redirect(url_for("parties"))
            else:
                flash(f"Allowed range: 1 <= max members <= {MAX_ALLOWED_MEMBERS}")
        else:
            flash("Party name taken")
    return render_template("create-party.html", user=current_user, form=form)


@app.route('/parties/join-party', methods=["POST"])
@login_only
def join_party():
    if request.method == "POST":
        user_id = current_user.id
        party_id = request.form['party_id']
        # check if joined party already
        find_member = PartyMembers.query.filter_by(user_id=user_id).filter_by(party_id=party_id).first()
        if find_member is None:
            party = Parties.query.filter_by(id=party_id).first()
            current_members = party.current_members
            max_members = party.max_members
            # check if at max capacity
            if current_members < max_members:
                party.current_members += 1
                new_member = PartyMembers(
                    user_id=user_id,
                    party_id=party_id
                )
                db.session.add(new_member)
                db.session.commit()
            else:
                flash("At max capacity :(")
        else:
            flash("Already joined!")
    return redirect(url_for("parties"))


@app.route('/parties/edit-party/<int:party_id>', methods=["GET", "POST"])
@login_only
def edit_party(party_id):
    party = Parties.query.filter_by(id=party_id).first()
    # check if non creator is trying to access other parties or non-existent parties
    if party is None or party.creator_id != current_user.id:
        flash("Not allowed to edit other parties, please login again")
        return redirect(url_for("login"))

    form = EditPartyForm(
        party_name=party.party_name,
        max_members=party.max_members,
        location=party.location,
        time=party.time
    )
    if form.validate_on_submit():
        # check if party name is unique
        find_party = Parties.query.filter_by(party_name=form.party_name.data).first()
        if find_party is None or find_party.id == party.id:
            if party.current_members <= form.max_members.data <= MAX_ALLOWED_MEMBERS:
                party.party_name = form.party_name.data
                party.max_members = form.max_members.data
                db.session.commit()
                return redirect(url_for("parties"))
            else:
                flash(f"Allowed range: {party.current_members} <= max members <= {MAX_ALLOWED_MEMBERS}")
        else:
            flash("Event name in use")
        return redirect(url_for("edit_party", party_id=party_id))
    return render_template("edit-party.html", form=form, user=current_user)


@app.route('/parties/delete-member/<int:member_id>/<int:party_id>')
@login_only
def delete_member(member_id, party_id):
    # check if non-member or non-creator is trying to delete other members
    creator_id = Parties.query.filter_by(id=party_id).first().creator_id
    if current_user.id != creator_id and current_user.id != member_id:
        flash("Not allowed to delete other party members, please login again")
        return redirect(url_for("login"))
    member = PartyMembers.query.filter_by(user_id=member_id).filter_by(party_id=party_id).first()
    db.session.delete(member)
    party = Parties.query.filter_by(id=party_id).first()
    party.current_members -= 1
    db.session.commit()
    return redirect(url_for("parties"))


@app.route('/parties/delete-party/<int:party_id>', methods=["GET", "POST"])
@login_only
def delete_party(party_id):
    party = Parties.query.filter_by(id=party_id).first()
    # check if non-party creator is trying to delete party
    if current_user.id != party.creator_id:
        flash("Not allowed to delete other parties, please login again")
        return redirect(url_for("login"))
    # delete party members to save space
    # sqlalchemy will also complain if party is deleted with party members not deleted
    all_party_members = PartyMembers.query.filter_by(party_id=party_id).all()
    for party_member in all_party_members:
        db.session.delete(party_member)
    db.session.delete(party)
    db.session.commit()
    return redirect(url_for("parties"))


if __name__ == "__main__":
    app.run(debug=True)
