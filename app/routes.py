from app import app, db
from flask import render_template, flash, url_for, redirect, request
from flask_login import current_user, login_user, logout_user, login_required
from forms import LoginForm, RegistrationForm, AddCategoryForm, AddTaskForm
from app.models import User, Category, Task
from werkzeug.urls import url_parse
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')
file_handler = logging.FileHandler('routes.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


@app.route('/')
@app.route('/index')
@login_required
def index():
    todo = []
    # tasks = Task.query.join(Category, Task.category_id == Category.id).filter(
    #     Category.user_id == current_user.id).all()
    category = set()
    categories = Category.query.filter_by(user_id=current_user.id).all()
    for c in categories:
        category.add(c.name)
        for task in c.tasks:
            todo.append({'taskid': task.id, 'task': task.name,
                         'category': task.category.name, 'priority': task.priority, 'time': task.timestamp})
    return render_template('index.html', title='Home', todo=todo, category=category)


@app.route('/<categoryName>')
@login_required
def filter(categoryName):
    todo = []
    category = set()
    categories = Category.query.filter_by(user_id=current_user.id).all()
    for c in categories:
        category.add(c.name)
        if c.name == categoryName:
            for task in c.tasks:
                todo.append({'taskid': task.id, 'task': task.name,
                             'category': task.category.name, 'priority': task.priority, 'time': task.timestamp})
    return render_template('index.html', title='Home', todo=todo, category=category)


@app.route('/login', methods=['POST', 'GET'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            logger.info('user "{}" logged in'.format(user.username))
            flash('Welocme '+form.username.data, 'success')
            login_user(user)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
            return redirect(next_page)
        flash('Invalid username-password combination', 'danger')
    return render_template('login.html', title='Log In', form=form)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration Successful', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/addCategory', methods=['POST', 'GET'])
@login_required
def add_category():
    # fetch all categories of user and check if the current one already exists
    categories = Category.query.filter_by(user_id=current_user.id).all()
    categoryList = [(str(c.id), c.name) for c in categories]

    form = AddCategoryForm()
    if form.validate_on_submit():
        for name in categoryList:
            if name == form.category.data.lower():
                flash('Category ' + form.category.data + ' already exists', 'danger')
                return redirect(url_for('add_category'))
        # add category to database
        logger.info(current_user.username + ' : added category : '+form.category.data)
        category = Category(name=form.category.data.lower(), user_id=current_user.id)
        db.session.add(category)
        db.session.commit()
        db.session.flush()
        categoryList.append((category.id, category.name))
        flash('Category ' + form.category.data + ' Added', 'success')
    return render_template('addCategory.html', title='Add Category', form=form, category=categoryList)


@app.route('/addTask', methods=['POST', 'GET'])
@login_required
def add_task():
    # fetch all categories added by user
    categories = Category.query.filter_by(user_id=current_user.id).all()
    tasks = Task.query.join(Category, Task.category_id == Category.id).filter(
        Category.user_id == current_user.id).all()

    if not categories:
        flash('You need to add a Category first', 'danger')
        return redirect(url_for('add_category'))

    items = [category.name for category in categories]

    form = AddTaskForm(items)
    # form.add_categories(items)
    if form.validate_on_submit():
        # check if task already exists
        for category in categories:
            if category.name == form.category.data.lower():
                for task in category.tasks:
                    if task.name.lower() == form.task.data.lower():
                        flash('Task "' + form.task.data +
                              '" already exists in '+category.name, 'danger')
                        return render_template('addTask.html', title='Add Task', form=form)
        # find category id of selected category
        category_id = 0
        for category in categories:
            if category.name == form.category.data.lower():
                category_id = category.id
                break
        # add to database
        task = Task(name=form.task.data.lower(),
                    priority=form.priority.data, category_id=category_id, user_id=current_user.id)

        db.session.add(task)
        db.session.commit()
        flash('Task ' + form.task.data + ' Added', 'success')
    return render_template('addTask.html', title='Add Task', form=form)


@app.route('/deleteTask/<int:userid>/<int:taskid>', methods=['GET', 'POST'])
@login_required
def delete_task(userid, taskid):
    if current_user.id == userid:
        task = Task.query.filter_by(id=taskid, user_id=userid).first()
        if not task:
            logger.error('No task for '+current_user.username+' with task id : '+str(taskid))
        else:
            logger.info('Task '+task.name+' deleted by '+current_user.username)
            db.session.delete(task)
            db.session.commit()
    else:
        logger.warning('User : ' + current_user.username +
                       ' tried to delete task of user id : '+str(userid))
    return redirect(url_for('index'))


@app.route('/deleteCategory/<int:userid>/<int:categoryid>', methods=['GET', 'POST'])
@login_required
def delete_category(userid, categoryid):
    if current_user.id == userid:
        category = Category.query.filter_by(id=categoryid, user_id=userid).first()
        if not category:
            logger.error('No category for '+current_user.username +
                         ' with category id : '+str(categoryid))
        else:
            tasks = list(category.tasks)
            if not tasks:
                db.session.delete(category)
                db.session.commit()
                flash('Category : '+category.name+' deleted ', 'success')
                logger.info("Category : "+category.name+" deleted by "+current_user.username)
            else:
                print list(category.tasks)
                flash('You have some tasks under this category!! Remove them first', 'danger')
            return redirect(url_for('add_category'))
    else:
        logger.warning('User : '+current_user.username +
                       ' tried to delete task of user id : '+str(userid))
    return redirect(url_for('add_category'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
