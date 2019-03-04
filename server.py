import jinja2
import base64
from aiohttp import web
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet
import aiosqlite
from passlib.hash import sha256_crypt

templateLoader = jinja2.FileSystemLoader(searchpath="./static")
templateEnv = jinja2.Environment(loader=templateLoader)
dbname = "users.db"

# checking sql string for preventing sql injection
def prevent_sql_injection_string(value):
    if (value is None or str(value).strip()==''):
        value = 'null'
    else:
        value = "'%s'" % str(value)
    return value
# insert SQL statement into db
async def insert_user_into_db(username, password):
    username = prevent_sql_injection_string(username)
    password = prevent_sql_injection_string(password)
    async with aiosqlite.connect(dbname) as db:
            await db.execute("INSERT INTO credentials (`username`, `password`) values(%s, %s)" % (username, password))
            await db.commit()
# select user from db
async def select_user(username):
    async with aiosqlite.connect(dbname) as db:
        cursor = await db.execute("SELECT * FROM credentials where username = %s" % prevent_sql_injection_string(username)) 
        row = await cursor.fetchone()
        await cursor.close()
        return row
# index page handler
async def handle(request):
    template = templateEnv.get_template('index.html')
    session = await get_session(request)
    user_name = session['login'] if 'login' in session else None
    if user_name is None:
        return web.HTTPFound('/login')
    else:
        rendered_index = template.render(user=user_name)
        return web.Response(body=rendered_index, content_type="text/html")
# login page handler
async def login_handle(request):
    template = templateEnv.get_template('login.html')
    rendered_login = template.render()
    return web.Response(text=rendered_login, content_type="text/html")
# check credentials of login and password parameters
async def check_credentials(username, password):
    if username is not None:
        row = await select_user(username)
        if row is not None:
            hash = row[2]
            try:
                return sha256_crypt.verify(password, hash)
            except:
                return False
                
    return False
# handler for checking login page credentials
async def check_login_handle(request):
    data = await request.post()
    login = data["login"]
    password = data["password"]
    if request.method == "POST":
        if await check_credentials(login, password) == True:
            session = await get_session(request)
            session['login'] = login
            return web.HTTPFound('/') 
        return web.Response(
            text='Wrong username/password combination', content_type="text/html")
# register page handler
async def register_handle(request):
    template = templateEnv.get_template('signup.html')
    rendered_signup = template.render()
    return web.Response(body=rendered_signup, content_type="text/html")
# handler for checking register page credentials  
async def signup_handle(request):
    body = await request.post()
    username = body["username"]
    password_1 = body["password"]
    password_2 = body["password2"]
    if username is not None and password_1 is not None and password_2 is not None:
        if password_1 == password_2:
            session = await get_session(request)
            session['login'] = username
            password_2 = sha256_crypt.hash("password")
            await insert_user_into_db(username, password_2)
            return web.HTTPFound('/')

app = web.Application()

fernet_key = fernet.Fernet.generate_key()
secret_key = base64.urlsafe_b64decode(fernet_key)
setup(app, EncryptedCookieStorage(secret_key))

app.add_routes([web.get('/', handle),
                web.get('/login', login_handle),
                web.post('/check-login', check_login_handle),
                web.get('/register', register_handle),
                web.post('/signup', signup_handle)])


web.run_app(app)