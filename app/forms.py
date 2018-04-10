from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import Email, EqualTo, DataRequired, ValidationError, Length
from app.models import User
from wtforms.fields.html5 import DateField


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=15)])
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=15)])
    repeat = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email.')


class AddCategoryForm(FlaskForm):
    category = StringField('Category', validators=[DataRequired()])
    submit = SubmitField('Add Category')


class AddTaskForm(FlaskForm):
    categories = []
    priorities = [('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')]
    category = SelectField('Category', choices=categories)
    task = StringField('Task', validators=[DataRequired()])
    priority = SelectField('Prioirty', choices=priorities)
    deadline = DateField('Deadline', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Add Task')

    def __init__(self, items, *args, **kwargs):
        super(AddTaskForm, self).__init__(*args, **kwargs)
        size = len(self.categories)
        for item in items:
            self.categories.append((item, item))
        for i in xrange(size):
            self.categories.pop(0)
