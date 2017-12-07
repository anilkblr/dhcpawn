# cob: type=views mountpoint=/
from cob import route
from flask import url_for, redirect
## Your routes go here
@route('/')
def index():
    return redirect(url_for('query.general_info'))
