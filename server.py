import jinja2
import base64
from aiohttp import web
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet

templateLoader = jinja2.FileSystemLoader(searchpath="./static")
templateEnv = jinja2.Environment(loader=templateLoader)

async def handle(request):
    template = templateEnv.get_template('index.html')
    session = await get_session(request)
    user_name = session['login'] if 'login' in session else None
    if user_name != "admin" or user_name is None:
        return web.HTTPFound('/login')
    rendered_index = template.render(name=user_name)
    return web.Response(body=rendered_index, content_type="text/html")
async def login_handle(request):
    template = templateEnv.get_template('login.html')
    rendered_login = template.render()
    return web.Response(text=rendered_login, content_type="text/html")
async def check_credentials(username, password):
    if username is not None:
        if username == "admin":
            if password == "admin":
                return True
    return False
async def check_login(request):
    data = await request.post()
    login = data["login"]
    password = data["password"]
    if request.method == "POST":
        if await check_credentials(login, password):
            session = await get_session(request)
            session['login'] = login
            return web.HTTPFound('/')
        return web.HTTPUnauthorized(
            body=b'Invalid username/password combination')

app = web.Application()

fernet_key = fernet.Fernet.generate_key()
secret_key = base64.urlsafe_b64decode(fernet_key)
setup(app, EncryptedCookieStorage(secret_key))

app.add_routes([web.get('/', handle),
                web.get('/login', login_handle),
                web.post('/check-login', check_login)])

web.run_app(app)