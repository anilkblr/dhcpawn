# cob: type=blueprint mountpoint=/tasks
from flask import Blueprint, jsonify, url_for, redirect
from .tasks import task_get_sync_stat, task_get_group_sync_stat
from . import methodviews as mv
from cob import task
from cob.app import build_app
from cob.celery.app import celery_app

api = Blueprint('tasksbp', __name__)

@api.route('/get_task_result/<task_id>', methods=['GET'])
def get_task_result(task_id):
    res = celery_app.AsyncResult(task_id)
    return jsonify({'task_status':res.status})

@api.route('/get_sync_stat_per_group/<int:group_id>', methods=['GET'])
def get_sync_stat_per_group(group_id):
    res = task_get_group_sync_stat.delay(group_id)
    return jsonify({'task_id':res.task_id})


@api.route('/get_sync_stat/', methods=['GET'])
def get_sync_stat():
    res = task_get_sync_stat.delay()
    return jsonify({'task_id':res.task_id})
