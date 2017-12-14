# cob: type=blueprint mountpoint=/tasks
from flask import Blueprint, jsonify
from cob.celery.app import celery_app

api = Blueprint('tasksbp', __name__)

@api.route('/get_task_result/<task_id>', methods=['GET'])
def get_task_result(task_id):
    res = celery_app.AsyncResult(task_id)
    return jsonify({'task_status':res.status})
