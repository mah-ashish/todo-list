# todo-list
A simple web app developed using flask framework

The initial version is deployed to Heroku: http://flask-to-do.herokuapp.com/

## Installation

#### Clone the repo

    git clone https://github.com/mah-ashish/todo-list.git

#### Install requirements using pip

    pip install -r `requirements.txt`

#### Create Tables in terminal

    python  
    from app import db  
    db.create_all()

#### For Windows

    set FLASK_APP=todo.py

#### For Linux

    export FLASK_APP=todo.py

#### To run the application type

    flask run
