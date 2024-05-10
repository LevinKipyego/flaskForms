from flask import Flask, request, render_template,flash, url_for, redirect
from datetime import datetime
from flask_wtf import FlaskForm, RecaptchaField
## from flask_recaptcha import ReCaptchaField
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, UserMixin, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_migrate import Migrate


app = Flask(__name__)
## configurations ##
app.config['SECRET_KEY'] = 'keyY123'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lf5p_4lAAAAAFuyPhyrWRwkqTl5O3LR8WJ0pwQu'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6Lf5p_4lAAAAAIl1LqENPuCGpIeHjGeoVeAaEkGS'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///form.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/form_db'
'''
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_DB'] = 'form_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
'''
#mysql = MySQL(app)

db = SQLAlchemy(app)
app.app_context().push()
#migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class FormFields(UserMixin, db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(10), nullable=False, unique=True)
    password = db.Column(db.String(15), nullable=False,)

    def __repr__(self):
        return '<Name %r>' % self.name

class RegForm(FlaskForm):
    name = StringField('Name', render_kw={"placeholder": "Enter your username"}, validators=[InputRequired('field should not be empty')])
    email = StringField('Email', render_kw={"placeholder": "Enter your email"}, validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    submit = SubmitField('register')

class LogInForm(FlaskForm):
    name = StringField('Name', render_kw={"placeholder": "Enter your username"}, validators=[InputRequired(message='username required')])
    #email = StringField('Email', render_kw={"placeholder": "Enter your email"}, validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired(message='password required')])
    boolean = BooleanField('Remember Me?')
    recap = RecaptchaField()
    submit = SubmitField('login')
    

@login_manager.user_loader
def load_user(user_id):
    return FormFields.query.get(int(user_id))

@app.route('/',methods=['POST', 'GET'])
@login_required
def dashboard():
    return render_template('dash.html', name=current_user.name)

@app.route('/register/',methods=['POST','GET'])
def register():
    form = RegForm()
    if request.method == 'POST' and form.validate_on_submit:
        name1 = form.name.data
        email1 = form.email.data
        password1 = form.password.data

        hashed_password = generate_password_hash(password1)
        fields = FormFields(name=name1, email=email1, password=hashed_password)
        try:
            db.session.add(fields)
            db.session.commit()
            
        except:
            return 'your username or email should be unique' 
        
    return render_template('register.html', form=form)


@app.route('/login/', methods=['POST', 'GET'])
def login():
    form = LogInForm()
    if request.method == 'POST' and form.validate_on_submit:
        user = FormFields.query.filter_by(name=form.name.data).first()
        if user:
           if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.boolean.data)
                return redirect(url_for('dashboard'))

        return '<h1> Invalid username or password </h1>'

    return render_template('login.html', form=form)

@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return '<h1> you have been logged out </h1>'

## error handler ##
'''
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(e):
    # handle the exception here
    return render_template('error.html'), 500

'''

if __name__ == '__main__':
    app.run(debug=True)