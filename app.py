# Import Flask, SQLAlchemy, Bcrypt, and Flask-Login
from flask import Flask, render_template, redirect,request, url_for, flash
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# Import Flask-Mail and itsdangerous
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
#import flask wtforms and radiofields to create quizz app
from flask_wtf import FlaskForm
from wtforms import RadioField, SubmitField
from random import sample

# Create the app and configure the database
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quizz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'your email'
app.config['MAIL_PASSWORD'] = 'your password'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Initialize the login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize the serializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Define a model class for users table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True )
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    college = db.Column(db.String(50), nullable=False)

# Define a user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import Flask-WTF and define the forms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

# Define a form for the login page
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define a form for the register page
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=10, max=10)])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    college = StringField('College', validators=[DataRequired(), Length(min=2, max=50)])
    submit = SubmitField('Register')

    # Define custom validators to check if the email or username already exists
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists.')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

# Define a form for the forgot password page
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

# Define a form for the reset password page
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
    
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200))
    options = db.relationship('Option', backref='question', lazy='dynamic')

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100))
    correct = db.Column(db.Boolean, default=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))

#quizz o quizz
class QuizForm(FlaskForm):
    # Dynamically generate the radio fields for the questions
    def __init__(self, questions):
        super(QuizForm, self).__init__()
        for question in questions:
            # Use the question id as the field name and the question text as the label
            setattr(self, str(question.id), RadioField(question.text, choices=[(option.id, option.text) for option in question.options], validators=[DataRequired()]))
        # Add a submit field to the form
        self.submit = SubmitField('Submit')
    
    

    app.url_map.strict_slashes = False

# Create a route for the login page
@app.route('/', methods=['GET','POST'])
def login():
    # Initialize the login form
    form = LoginForm()
    # Check if the form is valid
    if form.validate_on_submit():
        # Query the database for the user
        user = User.query.filter_by(username=form.username.data).first()
        # Check if the user exists and the password is correct
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # Log the user in and redirect to the home page
            login_user(user)
            return redirect(url_for('quiz'))
        else:
            # Flash an error message
            flash('Incorrect username or password.', 'danger')
    # Render the login template with the form
    return render_template('login.html', form=form)

@app.route('/register', methods=['POST','GET'])
def register():
    # Create the app context
    with app.app_context():
        # Initialize the register form
        form = RegisterForm()
        # Check if the form is valid
        if form.validate_on_submit():
            # Hash the password using Bcrypt
            password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            # Create a new user object
            user = User(name=form.name.data, email=form.email.data, password=password, phone=form.phone.data, username=form.username.data, college=form.college.data)
            try:
                # Create the tables if they don't exist
                db.create_all()
                # Add the user to the database
                db.session.add(user)
                # Commit the changes to the database
                db.session.commit()
                # Flash a success message
                flash('Account created successfully.', 'success')
                # Redirect the user to the login page
                return redirect(url_for('login'))
            except Exception as e:
                # Rollback the session in case of any error
                db.session.rollback()
                # Flash an error message
                flash(f'An error occurred: {e}', 'danger')
                # Log the error for debugging
                app.logger.error(f'An error occurred: {e}')
        # Render the register template with the form
        return render_template('registerform.html', form=form)

# Create a route for the home page
@app.route('/home')
@login_required
def home():
    # Render the home template
    return render_template('home.html')

# Create a route for the profile page
@app.route('/profile')
@login_required
def profile():
    # Query the database for the user
    user = User.query.filter_by(id=current_user.id).first()
    # Render the profile template with the user data
    return render_template('profile.html', user=user)

@app.route('/logout')
@login_required
def logout():
    # Log out the user and clear the session
    logout_user()
    # Flash a success message
    flash('You have logged out successfully.', 'success')
    # Redirect the user to the login page
    return redirect(url_for('login'))



@app.route('/quiz')
def quiz():
    # Get three random questions from the database
    questions = sample(Question.query.all(), 10)
    # Create the quiz form with the questions
    form = QuizForm(questions)
    # Render the quiz template with the form
    return render_template('quiz.html', form=form)

@app.route('/result', methods=['POST'])
def result():
    # Get the user answers from the form
    user_answers = request.form
    # Initialize the score and the feedback
    score = 0
    feedback = []
    # Loop through the user answers and check them against the database
    for question_id, option_id in user_answers.items():
        # Get the question and the option objects from the database
        question = Question.query.get(question_id)
        option = Option.query.get(option_id)
        # If the option is correct, increment the score and add a positive feedback
        if option.correct:
            score += 1
            feedback.append(f"Correct! {question.text} - {option.text}")
        # If the option is incorrect, add a negative feedback
        else:
            feedback.append(f"Incorrect! {question.text} - The correct answer is {question.options.filter_by(correct=True).first().text}")
    # Calculate the percentage of the score
    percentage = (score / 10) * 100
    # Flash the score and the feedback to the user
    flash(f"You scored {score} out of 10 ({percentage}%)", 'info')
    flash(feedback, 'info')
    # Redirect the user to the home page
    return redirect(url_for('home'))


# Create a route for the forgot password page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Initialize the forgot password form
    form = ForgotPasswordForm()
    # Check if the form is valid
    if form.validate_on_submit():
        # Query the database for the user
        user = User.query.filter_by(email=form.email.data).first()
        # Check if the user exists
        if user:
            # Generate a unique token
            token = s.dumps(user.email, salt='forgot-password')
            # Create a message object
            msg = Message('Password Reset Request', sender='your email', recipients=[user.email])
            # Add the link to the reset password page with the token as a query parameter
            link = url_for('reset_password', token=token, _external=True)
            # Add the body of the message
            msg.body = f'Hi {user.name},\n\nTo reset your password, please click on the link below:\n{link}\n\nIf you did not request a password reset, please ignore this email.'
            # Send the email
            mail.send(msg)
            # Flash a success message
            flash('A password reset link has been sent to your email.', 'success')
        else:
            # Flash an error message
            flash('No user with that email address.', 'danger')
    # Render the forgot password template with the form
    return render_template('forgot_password.html', form=form)

# Create a route for the reset password page
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Initialize the reset password form
    form = ResetPasswordForm()


# Run the app
if __name__ == '__main__':
    app.run(debug=True)