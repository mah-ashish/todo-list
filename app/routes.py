from app import app, db
from flask import render_template, flash, url_for, redirect, request
from flask_login import current_user, login_user, logout_user, login_required
from forms import LoginForm, RegistrationForm, AddCategoryForm, AddTaskForm
from app.models import User, Category, Task
from werkzeug.urls import url_parse
import logging
from datetime import datetime

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
    done = []
    category = set()
    categories = Category.query.filter_by(user_id=current_user.id).all()
    for c in categories:
        category.add(c.name)
        for task in c.tasks:
            if task.status == False:
                todo.append({'id': task.id, 'name': task.name,
                             'category': task.category.name, 'priority': task.priority,
                             'time': task.timestamp, 'deadline': task.deadline})
            else:
                done.append({'id': task.id, 'name': task.name,
                             'category': task.category.name, 'priority': task.priority,
                             'time': task.timestamp, 'deadline': task.deadline})
    return render_template('index.html', title='Home', todo=todo, done=done, category=category)


@app.route('/<categoryName>')
@login_required
def filter(categoryName):
    todo = []
    done = []
    category = set()
    categories = Category.query.filter_by(user_id=current_user.id).all()
    for c in categories:
        category.add(c.name)
        if c.name == categoryName:
            for task in c.tasks:
                if task.status == False:
                    todo.append({'id': task.id, 'name': task.name, 'category': task.category.name, 'priority': task.priority,
                                 'time': task.timestamp, 'deadline': task.deadline})
                else:
                    done.append({'id': task.id, 'name': task.name, 'category': task.category.name, 'priority': task.priority,
                                 'time': task.timestamp, 'deadline': task.deadline})
    flash('Filtering ToDo by '+categoryName, 'info')
    return render_template('index.html', title='Home', todo=todo, done=done, category=category)


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
    categoryList = [c.name for c in categories]

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
        categoryList.append(category.name)
        flash('Category ' + form.category.data + ' Added', 'success')
    return render_template('category.html', title='Add Category', form=form, category=categoryList)


@app.route('/deleteCategory/<category>', methods=['GET', 'POST'])
@login_required
def delete_category(category):
    c = Category.query.filter_by(name=category, user_id=current_user.id).first()
    if not c:
        logger.error('No category for '+current_user.username +
                     ' with category : ' + category)
    else:
        tasks = list(c.tasks)
        if not tasks:
            db.session.delete(c)
            db.session.commit()
            flash('Category : '+category+' deleted ', 'success')
            logger.info("Category : "+category+" deleted by "+current_user.username)
        else:
            flash('You have some tasks under this category!! Remove them first', 'warning')
    return redirect(url_for('index'))


@app.route('/editCategory/<category>', methods=['GET', 'POST'])
@login_required
def edit_category(category):
    categories = Category.query.filter_by(user_id=current_user.id).all()
    categoryList = [c.name for c in categories]
    if not categoryList or category not in categoryList:
        logger.error('No category for '+current_user.username +
                     ' with category : ' + category)
        return redirect(url_for('index'))
    form = AddCategoryForm()
    newCategory = None
    if form.validate_on_submit():
        if category == form.category.data.lower():
            flash('No changes were made', 'info')
            return redirect(url_for('index'))
        for c in categories:
            if c.name == form.category.data.lower():
                flash('Category ' + form.category.data + ' already exists', 'danger')
                return redirect(url_for('edit_category', category=category))
            if c.name == category:
                newCategory = c
        c.name = form.category.data.lower()
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('category.html', title='Edit Category', form=form, category=categoryList)


@app.route('/addTask', methods=['POST', 'GET'])
@login_required
def add_task():
    # fetch all categories added by user
    categories = Category.query.filter_by(user_id=current_user.id).all()
    tasks = Task.query.filter_by(user_id=current_user.id).all()

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
                        return render_template('task.html', title='Add Task', form=form)
        # find category id of selected category
        category_id = 0
        for category in categories:
            if category.name == form.category.data.lower():
                category_id = category.id
                break
        # add to database
        task = Task(name=form.task.data.lower(),
                    priority=form.priority.data, deadline=datetime.strptime(
                        form.deadline.data, '%Y/%m/%d'),
                    category_id=category_id, user_id=current_user.id)

        db.session.add(task)
        db.session.commit()
        flash('Task ' + form.task.data + ' Added', 'success')
    return render_template('task.html', title='Add Task', form=form)


@app.route('/deleteTask/<taskid>', methods=['GET', 'POST'])
@login_required
def delete_task(taskid):
    t = Task.query.filter_by(id=taskid, user_id=current_user.id).first()
    if not t:
        logger.error('No task for '+current_user.username+' with taskid : ' + str(taskid))
    else:
        logger.info('Task '+t.name+' deleted by '+current_user.username)
        flash('Task ' + t.name + ' deleted', 'info')
        db.session.delete(t)
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/editTask/<taskid>', methods=['GET', 'POST'])
@login_required
def edit_task(taskid):
    task = Task.query.filter_by(id=taskid, user_id=current_user.id).first()
    if not task:
        return redirect(url_for('index'))
    categories = Category.query.filter_by(user_id=current_user.id).all()
    items = [c.name for c in categories]
    form = AddTaskForm(items)
    if form.validate_on_submit():
        if form.category.data.lower() != task.category.name or form.task.data.lower() != task.name:
            c = Category.query.filter_by(
                user_id=current_user.id, name=form.category.data.lower()).first()
            if c:
                tasks = [task.name for task in c.tasks]
                if form.task.data.lower() in tasks:
                    flash('Task '+form.task.data+' already exists', 'warning')
                    return redirect(url_for('edit_task', taskid=taskid))

        task.name = form.task.data.lower()
        task.category_id = Category.query.filter_by(
            user_id=current_user.id, name=form.category.data.lower()).first().id
        task.deadline = datetime.strptime(form.deadline.data, '%Y/%m/%d')
        task.priority = form.priority.data
        db.session.commit()
        flash('Task edited', 'info')
        return redirect(url_for('index'))
    return render_template('task.html', title='Edit Task', form=form)


@app.route('/toggleTask/<taskid>', methods=['GET', 'POST'])
@login_required
def toggle_task(taskid):
    task = Task.query.filter_by(id=taskid, user_id=current_user.id).first()
    if not task:
        return redirect(url_for('index'))
    task.status = not task.status
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
