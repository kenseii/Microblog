import json
import sys
import time
from flask import render_template
from rq import get_current_job

from app import create_app, db
from app.email import send_email
from app.models import Task, User, Post

# instantiate a new flask as it is needed for the export

app = create_app()
app.app_context().push()


def example(seconds):
    # print task completed times the number of seconds given
    '''
    Instantiate the rq get current job to get a job instance
    write the percentage of completion to the meta dict and save it to redis
    the app can then read from the redis server to see the progress


    '''
    job = get_current_job()
    print('Starting task')
    for i in range(seconds):
        job.meta['progress'] = 100.0 * i / seconds
        # every time the meta is updated save the changes
        job.save_meta()
        print(i)
        # take a break of 1 sec
        time.sleep(1)
    job.meta['progress'] = 100
    job.save_meta()
    print('Task completed')


# write task progress on both job meta as well as the db

def _set_task_progress(progress):
    job = get_current_job()
    if job:
        job.meta['progress'] = progress
        job.save_meta()
        task = Task.query.get(job.get_id())
        task.user.add_notification('task_progress', {'task_id': job.get_id(),
                                                     'progress': progress})
        if progress >= 100:
            task.complete = True
        db.session.commit()


def export_posts(user_id):
    try:
        user = User.query.get(user_id)
        # first set the progress to 0 desho
        _set_task_progress(0)
        # set the data to export to empty desho
        data = []
        i = 0
        total_posts = user.posts.count()
        for post in user.posts.order_by(Post.timestamp.asc()):
            data.append({
                'body': post.body,
                'timestamp': post.timestamp.isoformat() + 'Z'
            })
            # this is because i have few data just to observe the progress
            time.sleep(5)
            i += 1
            _set_task_progress(100 * i // total_posts)
        send_email('[Microblog] Your blog posts',
                   sender=app.config['ADMINS'][0], recipients=[user.email],
                   text_body=render_template('email/export_posts.txt', user=user),
                   html_body=render_template('email/export_posts.html', user=user),
                   attachments=[('posts.json', 'application/json',
                                 json.dumps({'posts': data}, indent=4))],
                   sync=True

                   )
    except:
        _set_task_progress(100)
        app.logger.error('Unhandled exception', exc_info=sys.exc_info())
