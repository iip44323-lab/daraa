# -*- coding: utf-8 -*-
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import os

import config
from database import create_user, login_user, save_scan, get_user_scans
from scanner import full_scan

app = FastAPI(title='Daraa API')

app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

os.makedirs('static', exist_ok=True)
os.makedirs('templates', exist_ok=True)

app.mount('/static', StaticFiles(directory='static'), name='static')
templates = Jinja2Templates(directory='templates')


class RegisterReq(BaseModel):
    email: str
    password: str
    company: str
    phone: str


class LoginReq(BaseModel):
    email: str
    password: str


class ScanReq(BaseModel):
    url: str


@app.get('/', response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse('index.html', {'request': request})


@app.get('/register', response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse('register.html', {'request': request})


@app.get('/api')
def api_info():
    return {'name': 'Daraa API', 'status': 'ok', 'version': '1.0'}


@app.get('/health')
def health():
    return {'status': 'ok', 'time': datetime.now().isoformat()}


@app.post('/api/register')
def register(req: RegisterReq):
    uid = create_user(req.email, req.password, req.company, req.phone)
    if not uid:
        raise HTTPException(400, 'Email already registered')
    token = jwt.encode({'user_id': uid, 'exp': datetime.utcnow() + timedelta(days=7)}, config.SECRET_KEY, algorithm='HS256')
    return {'success': True, 'user_id': uid, 'token': token, 'trial_days': 7}


@app.post('/api/login')
def login(req: LoginReq):
    user = login_user(req.email, req.password)
    if not user:
        raise HTTPException(401, 'Wrong credentials')
    token = jwt.encode({'user_id': user[0], 'exp': datetime.utcnow() + timedelta(days=7)}, config.SECRET_KEY, algorithm='HS256')
    return {'success': True, 'user_id': user[0], 'email': user[1], 'company': user[2], 'plan': user[3], 'trial_ends': user[4], 'token': token}


@app.post('/api/scan')
async def scan(req: ScanReq, request: Request):
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        raise HTTPException(401, 'Token required')
    try:
        payload = jwt.decode(auth[7:], config.SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except Exception:
        raise HTTPException(401, 'Invalid token')
    result = full_scan(req.url)
    scan_id = save_scan(user_id, req.url, 'full', result['overall_score'], result)
    result['scan_id'] = scan_id
    return {'success': True, 'result': result}


@app.get('/api/scans')
def my_scans(request: Request):
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        raise HTTPException(401, 'Token required')
    try:
        payload = jwt.decode(auth[7:], config.SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except Exception:
        raise HTTPException(401, 'Invalid token')
    scans = get_user_scans(user_id)
    return {'scans': [{'id': s[0], 'url': s[1], 'score': s[2], 'date': s[3]} for s in scans]}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host=config.HOST, port=config.PORT)