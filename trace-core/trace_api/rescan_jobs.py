"""Persistent progress adapter for the existing scan progress API."""
import logging
from sqlalchemy import select, update
from .job_models import Job, RescanJob
from .job_store import status


def report(factory, job_id, phase, fraction, message):
    try:
        with factory() as db:
            db.execute(update(RescanJob).where(RescanJob.job_id == job_id).values(progress={
                'phase':phase, 'progress':max(0, min(1, float(fraction))), 'message':str(message or '')[:240]}))
            db.commit()
    except Exception:
        logging.getLogger(__name__).warning('Rescan progress update failed; Job status remains authoritative')


def progress(factory, scan_id, workspace_id, job_id=None):
    with factory() as db:
        query = select(RescanJob).join(Job, Job.id == RescanJob.job_id).where(
            Job.organization_id == 'default', Job.workspace_id == workspace_id, RescanJob.scan_id == scan_id)
        if job_id: query = query.where(Job.id == job_id)
        record = db.scalar(query.order_by(Job.created_at.desc(), Job.id.desc()).limit(1))
        if record is None:
            if job_id:
                from fastapi import HTTPException
                raise HTTPException(404, 'Задание пересчёта не найдено')
            return {'scanId':scan_id, 'phase':'idle', 'progress':0, 'message':None, 'active':False}
        data = dict(record.progress)
        selected = record.job_id
    job = status(factory, selected, workspace_id)
    data.update(scanId=scan_id, jobId=selected, active=job['status'] in ('queued', 'running'), requiresReview=job['requiresReview'])
    if job['status'] == 'queued': data.update(phase='queue', progress=0, message='постановка в очередь')
    elif job['status'] == 'completed': data.update(phase='done', progress=1, message='пересчёт завершён')
    elif job['status'] == 'cancelled': data.update(phase='cancelled', active=False, message='Пересчёт отменён до запуска')
    elif job['status'] == 'failed': data.update(phase='error', active=False, message='Пересчёт завершился ошибкой')
    elif job['requiresReview']: data.update(phase='interrupted', active=False, message='Состояние исполнителя требует проверки')
    elif data.get('phase') == 'done': data.update(phase='finalizing', progress=.99, message='сохранение статуса задания')
    return data
