from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import geocoder

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('✓ Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('⚠ Incorrect password, try again.', category='error')
        else:
            flash('⚠ Email does not exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/multilogue')
@login_required
def multilogue():
    return render_template("multilogue.html", user=current_user)

@auth.route('/dialogue')
@login_required
def dialogue():
    return render_template("dialogue.html", user=current_user)

@auth.route('/viewprofile')
@login_required
def viewprofile():
    return render_template("viewprofile.html", user=current_user)

@auth.route('/quiz')
@login_required
def quiz():
    return render_template("quiz.html", user=current_user)

@auth.route('/wouldyourather')
@login_required
def wouldyourather():
    return render_template("wouldyourather.html", user=current_user)

@auth.route('/war')
@login_required
def war():
    return render_template("war.html", user=current_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        phone_num = request.form.get('phoneNum')
        first_name = request.form.get('firstName')
        ref_code = request.form.get('refCode')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        #get location for flask

        user = User.query.filter_by(email=email).first()
        if user:
            flash('⚠ Email already exists.', category='error')
        elif len(email) < 4:
            flash('⚠ Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('⚠ First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('⚠ Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('⚠ Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, phone_num=phone_num,ref_code=ref_code, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('✓ Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign-up.html", user=current_user)