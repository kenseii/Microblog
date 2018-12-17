import time
from rq import get_current_job


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
