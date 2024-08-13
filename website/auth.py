from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from website import db
from website.models import User
import hashlib
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, please try again!', category='error')
        else:
            flash('Email does not exist', category='error')
    data = request.form
    print(data)
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        firstName = request.form.get('firstName')
        lastName = request.form.get('lastName')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exist', category='error')
        # elif len(firstName) or len(lastName) < 2:
        #     flash("The first name or last name is invalid", category='error')
        elif len(password1) < 4:
            flash("The password is invalid", category='error')
        elif password2 != password1:
            flash("The confirm passwords are not the same", category='error')
        elif len(email) < 7:
            flash("The email is invalid", category='error')
        else:
            hashed_password = hashlib.sha256(password1.encode('utf-8')).hexdigest()
            new_user = User(email=email, password=hashed_password, firstName=firstName, lastName=lastName)
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash("Account created successfully", category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)