import os
import sqlite3
import base64
import hashlib
from datetime import datetime
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, case
from sqlalchemy.orm import synonym
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_mail import Mail, Message
#python -m pip install --upgrade --force-reinstall ldap3
# LDAP support (ldap3)
try:
    from ldap3 import Server, Connection, ALL
except ImportError:
    Server = Connection = ALL = None

app = Flask(__name__)
app.config['SECRET_KEY'] = 'xp-legacy-secret-key'
# Если приложение работает за прокси/в Docker, доверяем заголовку X-Forwarded-For
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
# База данных SQLite — идеально для Windows Server 2016 без лишних настроек

basedir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(basedir, 'instance')
os.makedirs(instance_dir, exist_ok=True)

db_path = os.path.join(instance_dir, 'tickets.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
mail = Mail(app) if Mail else None

# --- МОДЕЛИ ДАННЫХ ---

class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    namesite = db.Column(db.String(100), default="Система заявок")
    logo_file = db.Column(db.String(100), nullable=True) # Здесь храним 'logo.png'


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50, collation='NOCASE'), nullable=False)  # Логин пользователя (sAMAccountName)
    domain_controller = db.Column(db.String(100), nullable=True)  # Контроллер домена (LDAP node)
    domain_name = db.Column(db.String(100), nullable=True)  # Домен (например, home.local)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'user' или 'admin'
    full_name = db.Column(db.String(100), nullable=True)  # ФИО из AD
    building = db.Column(db.String(50), nullable=True)  # Корпус
    room = db.Column(db.String(50), nullable=True)  # Кабинет
    phone = db.Column(db.String(20), nullable=True)  # Телефон
    mail = db.Column(db.String(100), nullable=True)  # Электронная почта для уведомлений
    computer_name = db.Column(db.String(100), nullable=True)  # Номер компьютера из профиля
    notify_by_email = db.Column(db.Boolean, default=False)  # Включать почтовые уведомления
    __table_args__ = (
        db.UniqueConstraint('username', 'domain_name', name='uix_username_domain_name'),
    )

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    computer_name = db.Column(db.String(100))
    status = db.Column(db.String(20), default='Новая')  # Новая, В работе, Закрыта
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('tickets', lazy=True))
    taken_by = db.Column(db.String(100), nullable=True)  # Кто взял в работу (ФИО или username)
    comments = db.relationship('Comment', backref='ticket', lazy='joined', cascade='all, delete-orphan')
    building = db.Column(db.String(50), nullable=True)  # Корпус
    room = db.Column(db.String(50), nullable=True)  # Кабинет
    phone = db.Column(db.String(20), nullable=True)  # Телефон
    ip_address = db.Column(db.String(45))  # IPv4 или IPv6
    domain_info = db.Column(db.String(100)) # Домен (например, home.local)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('comments', lazy=True))

class LdapSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    connection_name = db.Column(db.String(100)) # "Новое подключение"
    domain_name = db.Column(db.String(100))     # domain.local
    server_ip = db.Column(db.String(100))       # IP сервера
    base_dn = db.Column(db.String(200))         # Путь к OU
    service_account = db.Column(db.String(100)) # Логин
    password = db.Column(db.String(100))        # Пароль
    service_password = synonym('password')
    admin_group_cn = db.Column(db.String(100))  # Название группы админов
    admin_group_dn = db.Column(db.String(200))  # Полный путь группы

class MailConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(100))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_user = db.Column(db.String(100))
    smtp_password = db.Column(db.String(100))
    use_tls = db.Column(db.Boolean, default=True)
    use_ssl = db.Column(db.Boolean, default=False)
    sender_email = db.Column(db.String(100))

class ServiceEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

# --- ФУНКЦИИ УВЕДОМЛЕНИЙ ---

def update_mail_settings(config=None):
    """Обновляет конфигурацию Flask-Mail из БД или из переданного объекта."""
    if config is None:
        config = MailConfig.query.first()
    if config and config.smtp_server:
        app.config.update(
            MAIL_SERVER=config.smtp_server,
            MAIL_PORT=config.smtp_port,
            MAIL_USE_TLS=config.use_tls,
            MAIL_USE_SSL=config.use_ssl,
            MAIL_USERNAME=config.smtp_user,
            MAIL_PASSWORD=decrypt_mail_password(config.smtp_password),
            MAIL_DEFAULT_SENDER=("Система заявок", config.sender_email or config.smtp_user)
        )
        if mail:
            mail.init_app(app)
        return True
    return False

def send_async_email(app_instance, msg):
    with app_instance.app_context():
        try:
            if mail:
                mail.send(msg)
        except Exception as e:
            print(f"Ошибка отправки: {e}")


def get_ldap_settings():
    """Возвращает первую доступную конфигурацию LDAP или None."""
    return LdapSetting.query.first()

def get_ldap_setting_by_id(ldap_id):
    """Возвращает конфигурацию LDAP по ID."""
    return LdapSetting.query.get(ldap_id)


def _get_cipher_key():
    secret = app.config.get('LDAP_SECRET_KEY') or app.config.get('SECRET_KEY') or 'ldap-fallback-secret'
    return hashlib.sha256(secret.encode('utf-8')).digest()


def encrypt_secret_value(value):
    if value is None:
        return None
    raw = value.encode('utf-8')
    key = _get_cipher_key()
    salt = os.urandom(16)
    cipher = bytes([raw[i] ^ key[i % len(key)] for i in range(len(raw))])
    token = base64.urlsafe_b64encode(salt + cipher).decode('ascii')
    return f'ENC:{token}'


def decrypt_secret_value(value):
    if not value:
        return ''
    if not isinstance(value, str) or not value.startswith('ENC:'):
        return value
    try:
        token = value[4:]
        decoded = base64.urlsafe_b64decode(token.encode('ascii'))
        if len(decoded) <= 16:
            return ''
        cipher = decoded[16:]
        key = _get_cipher_key()
        raw = bytes([cipher[i] ^ key[i % len(key)] for i in range(len(cipher))])
        return raw.decode('utf-8')
    except Exception:
        return value


def encrypt_ldap_password(password):
    return encrypt_secret_value(password)


def decrypt_ldap_password(value):
    return decrypt_secret_value(value)


def encrypt_mail_password(password):
    return encrypt_secret_value(password)


def decrypt_mail_password(value):
    return decrypt_secret_value(value)


def test_ldap_connection(settings_data):
    """Проверить соединение по введенным настройкам (или по уже сохраненным)."""
    if Server is None:
        return False, 'Не установлена библиотека ldap3. Установите через pip install ldap3.'

    server_ip = settings_data.get('server_ip')
    service_account = settings_data.get('service_account')
    service_password = settings_data.get('password')

    if not server_ip or not service_account or not service_password:
        return False, 'В настройках LDAP должны быть указаны server_ip, service_account и пароль.'

    server_uri = f"ldap://{server_ip}"
    server = Server(server_uri, get_info=ALL)

    try:
        conn = Connection(server, user=service_account, password=service_password, auto_bind=True)
        conn.unbind()
        return True, 'Соединение установлено успешно.'
    except Exception as e:
        return False, str(e)

def authenticate_ldap_user(username, password, ldap_config_id=None):
    """Попытка аутентификации пользователя через LDAP.
    Возвращает (True, user_dn) при успехе и (False, сообщение) при неудаче.
    """
    if Server is None:
        return False, 'Не установлена библиотека ldap3.'

    cfg = get_ldap_settings() if ldap_config_id is None else get_ldap_setting_by_id(ldap_config_id)
    if not cfg:
        return False, 'LDAP не настроен или выбран неверный профиль.'

    server_uri = f"ldap://{cfg.server_ip}"
    server = Server(server_uri, get_info=ALL)

    try:
        admin_password = decrypt_ldap_password(cfg.password)
        admin_conn = Connection(server, user=cfg.service_account, password=admin_password, auto_bind=True)
    except Exception as e:
        return False, f'Не удалось подключиться как сервисный аккаунт: {e}'

    search_base = cfg.base_dn or cfg.domain_name or ''
    if not search_base:
        return False, 'Не указан base_dn или domain_name в настройках LDAP.'

    search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
    try:
        if not admin_conn.search(search_base, search_filter, attributes=['distinguishedName', 'memberOf', 'displayName']):
            admin_conn.unbind()
            return False, 'Пользователь в LDAP не найден.'

        entry = admin_conn.entries[0]
        user_dn = entry.entry_dn
        member_of = entry.memberOf.values if hasattr(entry, 'memberOf') else []
        full_name = entry.displayName.value if hasattr(entry, 'displayName') and entry.displayName.value else None

        is_admin = False
        if cfg.admin_group_dn:
            is_admin = any(cfg.admin_group_dn.lower() in m.lower() for m in member_of)
        elif cfg.admin_group_cn:
            # проверяем CN=adminKB часть
            is_admin = any(f'CN={cfg.admin_group_cn.lower()}' in m.lower() for m in member_of)

        admin_conn.unbind()
    except Exception as e:
        admin_conn.unbind()
        return False, f'Ошибка поиска пользователя в LDAP: {e}'

    try:
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()
        return True, {'user_dn': user_dn, 'is_admin': is_admin, 'full_name': full_name}
    except Exception as e:
        return False, f'Не удалось выполнить bind за пользователя: {e}'

# --- ИНИЦИАЛИЗАЦИЯ БД ---

with app.app_context():
    db.create_all()
    # Миграция для SQLite: добавляем domain_controller, если еще нет
    sqlite_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if sqlite_uri.startswith('sqlite:///'):
        db_path = sqlite_uri.replace('sqlite:///', '')
        if os.path.exists(db_path):
            con = sqlite3.connect(db_path)
            cols = [row[1] for row in con.execute("PRAGMA table_info(user)")]
            if 'domain_controller' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN domain_controller TEXT")
            if 'full_name' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN full_name TEXT")
            if 'building' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN building TEXT")
            if 'room' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN room TEXT")
            if 'phone' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN phone TEXT")
            if 'computer_name' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN computer_name TEXT")
            if 'notify_by_email' not in cols:
                con.execute("ALTER TABLE user ADD COLUMN notify_by_email BOOLEAN DEFAULT 0")

            table_sql = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='user'").fetchone()
            has_legacy_unique = False
            if table_sql and 'UNIQUE (USERNAME)' in table_sql[0].upper():
                has_legacy_unique = True

            if has_legacy_unique:
                con.execute('PRAGMA foreign_keys=OFF')
                con.execute('BEGIN')
                con.execute('''CREATE TABLE IF NOT EXISTS user_new (
                    id INTEGER NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    password VARCHAR(100) NOT NULL,
                    role VARCHAR(10),
                    domain_controller TEXT,
                    full_name TEXT,
                    building TEXT,
                    room TEXT,
                    phone TEXT,
                    PRIMARY KEY (id)
                )''')
                con.execute('''INSERT OR IGNORE INTO user_new (id, username, password, role, domain_controller, full_name, building, room, phone)
                    SELECT id, username, password, role, domain_controller, full_name, building, room, phone FROM user''')
                con.execute('DROP TABLE user')
                con.execute('ALTER TABLE user_new RENAME TO user')
                con.execute('PRAGMA foreign_keys=ON')
                con.commit()

            # Удаляем старый индекс, если он остался в списке
            index_names = [row[1] for row in con.execute("PRAGMA index_list('user')")]
            if 'sqlite_autoindex_user_1' in index_names:
                try:
                    con.execute("DROP INDEX IF EXISTS sqlite_autoindex_user_1")
                except sqlite3.OperationalError:
                    pass

            # Создаем уникальный индекс по username + domain_controller
            con.execute("CREATE UNIQUE INDEX IF NOT EXISTS uix_username_domain_controller ON user (username, domain_controller)")
            con.commit()

            # Миграция для ticket
            ticket_cols = [row[1] for row in con.execute("PRAGMA table_info(ticket)")]
            if 'building' not in ticket_cols:
                con.execute("ALTER TABLE ticket ADD COLUMN building TEXT")
            if 'room' not in ticket_cols:
                con.execute("ALTER TABLE ticket ADD COLUMN room TEXT")
            if 'phone' not in ticket_cols:
                con.execute("ALTER TABLE ticket ADD COLUMN phone TEXT")
            con.commit()
            con.close()

    # Создаем тестового админа, если его нет
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('ytcrf;e'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

    # Шифруем существующий пароль сервисной почты, если он хранится в открытом виде
    mail_config_obj = MailConfig.query.first()
    if mail_config_obj and mail_config_obj.smtp_password and not mail_config_obj.smtp_password.startswith('ENC:'):
        mail_config_obj.smtp_password = encrypt_mail_password(mail_config_obj.smtp_password)
        db.session.commit()

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(user=user)
    return dict(user=None)

@app.context_processor
def inject_cfg():
    cfg = get_ldap_settings()
    return dict(cfg=cfg)


def get_client_ip():
    """Возвращает реальный IP клиента с учётом X-Forwarded-For."""
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr or ''


def notify(subject, recipient_email, html_body):
    """Отправка уведомления (поддерживает HTML)"""
    if not recipient_email or not mail:
        return

    if update_mail_settings():
        msg = Message(subject, recipients=[recipient_email])
        msg.html = html_body # Используем HTML для красоты
        threading.Thread(target=send_async_email, args=(app, msg)).start()

def notify(subject, recipient_email, html_body):
    """Главная функция уведомления"""
    if not recipient_email:
        return

    recipient_user = User.query.filter_by(mail=recipient_email).first()
    if recipient_user and not getattr(recipient_user, 'notify_by_email', False):
        return

    if update_mail_settings():
        msg = Message(subject, recipients=[recipient_email])
        msg.html = html_body
        # Запуск в отдельном потоке, чтобы не тормозить UI
        threading.Thread(target=send_async_email, args=(app, msg)).start()

# --- МАРШРУТЫ (ROUTES) ---

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    q = request.args.get('q', '').strip()
    tab = request.args.get('tab', 'all').strip()  # new, inprogress, closed, all
    selected_ticket_id = request.args.get('selected', type=int)

    query = Ticket.query
    if user.role != 'admin':
        query = query.filter_by(user_id=user.id)

    if q:
        search_value = q[1:].strip() if q.startswith('#') else q
        if search_value.isdigit() and (q.startswith('#') or q.isdigit()):
            query = query.filter(Ticket.id == int(search_value))
        else:
            like_q = f"%{q}%"
            ticket_conditions = [
                Ticket.title.ilike(like_q),
                Ticket.description.ilike(like_q),
                Ticket.ip_address.ilike(like_q),
                Ticket.domain_info.ilike(like_q),
                Ticket.computer_name.ilike(like_q),
                Ticket.building.ilike(like_q),
                Ticket.room.ilike(like_q),
                Ticket.phone.ilike(like_q),
                Ticket.status.ilike(like_q)
            ]
            if search_value.isdigit():
                ticket_conditions.append(Ticket.id == int(search_value))

            query = query.join(User, Ticket.author).filter(
                or_(
                    *ticket_conditions,
                    User.username.ilike(like_q),
                    User.domain_controller.ilike(like_q),
                    User.full_name.ilike(like_q)
                )
            )

    status_priority = case(
        {
            'В работе': 1,
            'Новая': 2,
            'Закрыта': 3
        },
        value=Ticket.status
    )

    if tab == 'new':
        query = query.filter(Ticket.status == 'Новая')
    elif tab == 'inprogress':
        query = query.filter(Ticket.status == 'В работе')
    elif tab == 'closed':
        query = query.filter(Ticket.status == 'Закрыта')

    # 3. ТЕПЕРЬ используем status_priority в сортировке
    query = query.order_by(status_priority, Ticket.created_at.desc())

    # 4. Выполняем запрос к БД
    # Настройка пагинации
    page = request.args.get('page', 1, type=int)
    per_page = 6  # Количество заявок на одну страницу (чтобы влезло без скролла)
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    tickets = pagination.items


    # 5. И только в самом конце логика выбора selected_ticket
    selected_id = request.args.get('selected', type=int)
    selected_ticket = None
    if selected_id:
        selected_ticket = Ticket.query.get(selected_id)

    if selected_ticket_id:
        # Ищем заявку по ID
        ticket_to_check = Ticket.query.get(selected_ticket_id)
        
        if ticket_to_check:
            # Если админ — показываем. Если юзер — только если он автор.
            if user.role == 'admin' or ticket_to_check.user_id == user.id:
                selected_ticket = ticket_to_check
            else:
                # Если доступа нет, можно выдать ошибку или просто не показывать
                flash('У вас нет прав для просмотра этой заявки')
                selected_ticket = None

    if not selected_ticket and tickets:
        selected_ticket = tickets[0]

    # Счётчики вкладок
    if user.role == 'admin':
        counts = {
            'new': Ticket.query.filter_by(status='Новая').count(),
            'inprogress': Ticket.query.filter_by(status='В работе').count(),
            'closed': Ticket.query.filter_by(status='Закрыта').count(),
            'all': Ticket.query.count()
        }
    else:
        counts = {
            'new': Ticket.query.filter_by(status='Новая', user_id=user.id).count(),
            'inprogress': Ticket.query.filter_by(status='В работе', user_id=user.id).count(),
            'closed': Ticket.query.filter_by(status='Закрыта', user_id=user.id).count(),
            'all': Ticket.query.filter_by(user_id=user.id).count()
        }

    return render_template('index.html', 
                           tickets=tickets, 
                           pagination=pagination, # Добавлено
                           user=user, q=q, tab=tab,
                           selected_ticket=selected_ticket, 
                           counts=counts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    ldap_configs = LdapSetting.query.all()
    if request.method == 'POST':
        username = request.form.get('username').lower()
        password = request.form.get('password')
        selected_ldap_id = request.form.get('ldap_connection')

        # Локальная авторизация (без контроллера, legacy)
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.username == 'admin' or user.domain_controller in (None, ''):
                session['user_id'] = user.id
                return redirect(url_for('index'))

        # LDAP авторизация с выбранной конфигурацией
        ldap_config = get_ldap_setting_by_id(selected_ldap_id) if selected_ldap_id else get_ldap_settings()
        ldap_server = ldap_config.server_ip if ldap_config else ''
        ldap_ok, ldap_result = authenticate_ldap_user(username, password, ldap_config.id if ldap_config else None)

        if ldap_ok:
            domain_controller = ldap_server or ''
            domain_name=ldap_config.domain_name if ldap_config else ''
            if isinstance(domain_name, tuple):
                domain_name = domain_name[0]
            user = User.query.filter_by(username=username, domain_controller=domain_controller).first()
            role = 'admin' if ldap_result.get('is_admin') else 'user'
            full_name = ldap_result.get('full_name', username)

            if not user:
                user = User(
                    username=username,
                    domain_controller=domain_controller,
                    domain_name=domain_name, # Сохраняем home.local
                    password=generate_password_hash(password),
                    role=role,
                    full_name=full_name
                )
                db.session.add(user)
            else:
                if user.role != role:
                    user.role = role
                if not user.full_name:
                    user.full_name = full_name
                if ldap_config:
                    user.domain_name = ldap_config.domain_name

            
            db.session.commit()
            session['user_id'] = user.id
            # уведомление над хэдером
            # flash('Успешная авторизация через LDAP')
            if not user.building or not user.room or not user.phone or user.full_name == '':
                return redirect(url_for('profile'))
            elif user.role == 'admin':
                return redirect(url_for('index'))
            else:
                return redirect(url_for('index'))
            
            
        flash(f'Неверное имя пользователя или пароль. LDAP: {ldap_result}')

        flash(f'Неверное имя пользователя или пароль. LDAP: {ldap_result}')

    return render_template('login.html', configs=ldap_configs)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Маршрут создания новой заявки.
@app.route('/create', methods=['GET', 'POST'])
def create_ticket():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user_ip = get_client_ip()
    current_domain = user.domain_name if user.domain_name else "Локально"

    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        computer_name = request.form.get('computer_name') or user.computer_name
        building = request.form.get('building')
        room = request.form.get('room')
        phone = request.form.get('phone')
        user_ip = get_client_ip()  # Определяем IP и Домен
        current_domain = user.domain_name if user.domain_name else "Локально"
        new_ticket = Ticket(
            title=title,
            description=description,
            computer_name=computer_name,
            building=building,
            room=room,
            phone=phone,
            user_id=session['user_id'],
            taken_by=user.full_name or user.username,
            ip_address=user_ip,       # Сохраняем IP
            domain_info=current_domain  # Сохраняем Домен
        )
        try:
            db.session.add(new_ticket)
            db.session.commit()

            # Извлекаем только текстовые адреса в список
            service_emails_records = ServiceEmail.query.all()
            service_emails = [item.email for item in service_emails_records]

            if  user.role == 'user':
                html = f"""<p>Пользователь {user.full_name or user.username} создал новую заявку:</p>"""
                html += f"<p><strong>{new_ticket.title}</strong></p>"
                html += f"<p>{new_ticket.description}</p>"
                for email in service_emails:
                    notify('Новая заявка от ' + (user.full_name or user.username), email, html)
            

            flash('Заявка успешно создана!')
            # Передаем tab='new' и ID новой заявки, чтобы она сразу открылась
            return redirect(url_for('index', tab='new', selected=new_ticket.id))
        except Exception as e:
            db.session.rollback()
            return f"Ошибка базы данных: {e}"
    
    return render_template('create.html')

@app.route('/edit/<int:ticket_id>', methods=['GET', 'POST'])
def edit_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    ticket = Ticket.query.get_or_404(ticket_id)

    # Проверяем, что пользователь может редактировать эту заявку (своя или админ)
    if ticket.user_id != user.id and user.role != 'admin':
        flash('Доступ запрещен')
        return redirect(url_for('index'))
    
    # Проверка статуса, заявку в работе или закрытую нельзя редактировать пользователю
    if ticket.status in ['В работе', 'Закрыта'] and user.role != 'admin':
        flash('Редактирование невозможно: заявку взяли в работу или она уже закрыта')
        return redirect(url_for('index', selected=ticket.id))

    if request.method == 'POST':
        action = request.form.get('action', 'save')
        
        if action == 'comment':
            # Добавляем только комментарий
            new_comment = request.form.get('comment')
            if new_comment and new_comment.strip():
                comment = Comment(text=new_comment, user_id=session['user_id'], ticket_id=ticket_id)
                db.session.add(comment)
            try:
                db.session.commit()
                # flash('Комментарий добавлен')
            except Exception as e:
                db.session.rollback()
                flash(f'Ошибка: {e}')
            return redirect(url_for('edit_ticket', ticket_id=ticket_id))
        else:
            # Сохраняем основные поля заявки
            title = request.form.get('title')
            status = request.form.get('status')
            description = request.form.get('description')
            computer_name = request.form.get('computer_name')
            building = request.form.get('building')
            room = request.form.get('room')
            phone = request.form.get('phone')
            
            ticket.title = title
            ticket.status = status
            ticket.description = description
            ticket.computer_name = computer_name
            ticket.building = building
            ticket.room = room
            ticket.phone = phone
            
            try:
                db.session.commit()
                flash('Заявка обновлена')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash(f'Ошибка: {e}')

    return render_template('edit.html', item=ticket)


@app.route('/update_status/<int:ticket_id>/<string:new_status>')
def update_status(ticket_id, new_status):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    if user.role != 'admin':
        flash('Доступ запрещен')
        return redirect(url_for('index'))

    ticket = Ticket.query.get_or_404(ticket_id)
    ticket.status = new_status
    db.session.commit()

    if ticket.status == 'В работе':
        ticket.taken_by = user.full_name or user.username

    # --- БЛОК УВЕДОМЛЕНИЯ ПОЛЬЗОВАТЕЛЯ ПО ПОЧТЕ О СТАТУСЕ ЗАЯВКИ---
    if ticket.author and ticket.author.mail:
        subject = f"Обновление статуса заявки №{ticket.id}"
        
        # Формируем текст в зависимости от статуса
        status_text = new_status
        if new_status == 'В работе':
            body = f"Ваша заявка {ticket.id} «{ticket.title}» принята в работу."
        elif new_status == 'Закрыта':
            body = f"Ваша заявка #{ticket.id} «{ticket.title}» закрыта."
        else:
            body = f"Статус вашей заявки {ticket.id} «{ticket.title}» изменен на: {new_status}."

        html = f"""
        <p>{body}</p>
        <hr>
        <p><small>Это автоматическое уведомление от {global_name if 'global_name' in locals() else 'Системы заявок'}</small></p>
        """
        
        notify(subject, ticket.author.mail, html)
    # ---------------------------------------

    selected_ticket_id = request.args.get('selected', ticket_id)
    current_tab = request.args.get('tab', '').strip()

    # При смене статуса автоматически остаёмся на релевантной вкладке,
    # и сохраняем выбранную заявку в параметре selected.
    if current_tab not in ['new', 'inprogress', 'closed', 'all']:
        current_tab = 'closed' if new_status == 'Закрыта' else 'inprogress' if new_status == 'В работе' else 'all'

    return redirect(url_for('index', tab=current_tab, selected=selected_ticket_id))


@app.route('/delete_ticket/<int:ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    ticket = Ticket.query.get_or_404(ticket_id)

    can_delete = False
    if user.role == 'admin':
        can_delete = True
    elif ticket.user_id == user.id and ticket.status == 'Новая' and len(ticket.comments) == 0:
        can_delete = True

    if not can_delete:
        flash('Вы не можете удалить эту заявку')
        return redirect(url_for('index', selected=ticket_id))

    try:
        db.session.delete(ticket)
        db.session.commit()
        flash(f'Заявка #{ticket_id} удалена')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка удаления: {e}')

    return redirect(url_for('index'))


@app.route('/add_comment/<int:ticket_id>', methods=['POST'])
def add_comment(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    ticket = Ticket.query.get_or_404(ticket_id)

    if user.role != 'admin' and ticket.user_id != user.id:
        flash('Доступ запрещен')
        return redirect(url_for('index'))
    
    text = request.form.get('comment', '').strip()
    if text:
        comment = Comment(text=text, user_id=user.id, ticket_id=ticket_id)
        db.session.add(comment)
        db.session.commit()


         # Извлекаем только текстовые адреса в список
        service_emails_records = ServiceEmail.query.all()
        service_emails = [item.email for item in service_emails_records]

        if  user.role == 'user':
            html = f"""<p>Пользователь {user.full_name or user.username} добавил комментарий к заявке [{ticket.id}]:</p>"""
            html += f"<p><strong>{comment.text}</strong></p>"
            
            for email in service_emails:
                notify('Новый комментарий от ' + (user.full_name or user.username), email, html)
        elif user.role == 'admin':
            html = f"""<p>Администратор {user.full_name or user.username} добавил комментарий к заявке [{ticket.id}]:</p>"""
            html += f"<p><strong>{comment.text}</strong></p>"

            if ticket.author and ticket.author.mail:
                notify('Новый комментарий от администратора', ticket.author.mail, html)


        # flash('Комментарий добавлен.')
    else:
        flash('Комментарий не может быть пустым.')

    return redirect(url_for('index', tab=request.args.get('tab', 'active'), selected=ticket_id))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or (user.role != 'admin' and not getattr(user, 'is_admin', False)):
        flash('Доступ только для администраторов')
        return redirect(url_for('index'))
    
    # 1. Загружаем настройки сайта (логотип и название)
    config = SiteSettings.query.first()
    if not config:
        config = SiteSettings(namesite="Система заявок")
        db.session.add(config)
        db.session.commit()

    logo_url = url_for('static', filename='uploads/' + config.logo_file) if config.logo_file else None

    # 2. Загружаем конфигурации LDAP и Почты
    ldap_configs = LdapSetting.query.all()
    mail_config = MailConfig.query.first()
    if not mail_config:
        mail_config = MailConfig()
        db.session.add(mail_config)
        db.session.commit()
    service_emails = ServiceEmail.query.all()

    # 3. Обработка POST-запросов
    if request.method == 'POST':
        action = request.form.get('action')
        mail_action = request.form.get('mail_action')

        # --- СМЕНА НАЗВАНИЯ САЙТА ---
        if action == 'update_site_name':
            new_name = request.form.get('site_name')
            if new_name:
                config.namesite = new_name
                db.session.commit()
                flash('Название системы обновлено!')
            return redirect(url_for('settings'))

        # --- ЛОГИКА ПОЧТЫ (Добавление/Удаление/Сохранение/Тест) ---
        if mail_action == 'add_email':
            email_addr = request.form.get('new_service_email')
            if email_addr:
                new_e = ServiceEmail(email=email_addr)
                db.session.add(new_e)
                db.session.commit()
                flash(f'Адрес {email_addr} добавлен')
            return redirect(url_for('settings'))

        if mail_action == 'delete_email':
            email_id = request.form.get('email_id')
            if email_id:
                email_to_del = ServiceEmail.query.get(email_id)
                if email_to_del:
                    db.session.delete(email_to_del)
                    db.session.commit()
                    flash('Email удален из списка рассылки')
            return redirect(url_for('settings'))

        if mail_action == 'save':
            mail_config.smtp_server = request.form.get('smtp_server')
            mail_config.smtp_port = int(request.form.get('smtp_port', 587))
            mail_config.smtp_user = request.form.get('smtp_user')
            password_input = request.form.get('smtp_password')
            if password_input:
                mail_config.smtp_password = encrypt_mail_password(password_input)
            mail_config.sender_email = request.form.get('sender_email')
            mail_config.use_tls = 'use_tls' in request.form
            mail_config.use_ssl = 'use_ssl' in request.form
            db.session.commit()
            flash('Настройки почты сохранены')
            return redirect(url_for('settings'))

        if mail_action == 'test':
            recipient = request.form.get('test_email')
            if recipient:
                form_password = request.form.get('smtp_password')
                test_password = form_password if form_password else decrypt_mail_password(mail_config.smtp_password)
                test_config = MailConfig(
                    smtp_server=request.form.get('smtp_server'),
                    smtp_port=int(request.form.get('smtp_port', 587)),
                    smtp_user=request.form.get('smtp_user'),
                    smtp_password=encrypt_mail_password(test_password) if test_password else None,
                    sender_email=request.form.get('sender_email'),
                    use_tls='use_tls' in request.form,
                    use_ssl='use_ssl' in request.form
                )

                if update_mail_settings(test_config):
                    try:
                        msg = Message("Тестовое сообщение", recipients=[recipient])
                        msg.body = "Это проверочное письмо от Системы заявок."
                        mail.send(msg)
                        flash(f'Тестовое письмо успешно отправлено на {recipient}')
                    except Exception as e:
                        flash(f'Ошибка отправки: {str(e)}')
            return redirect(url_for('settings'))

        # --- ЛОГИКА LDAP (Test/Save) ---
        if action in ['save', 'test']:
            # Собираем данные в словарь settings_data для передачи в шаблон при ошибке
            settings_data = {
                'id': request.form.get('id'),
                'connection_name': request.form.get('connection_name'),
                'domain_name': request.form.get('domain_name'),
                'server_ip': request.form.get('server_ip'),
                'base_dn': request.form.get('base_dn'),
                'service_account': request.form.get('service_account'),
                'password': request.form.get('password'),
                'admin_group_cn': request.form.get('admin_group_cn'),
                'admin_group_dn': request.form.get('admin_group_dn')
            }
            # Пароль берем отдельно
            password = request.form.get('password')
            conf_id = settings_data['id']
            conf = None

            if conf_id:
                conf = LdapSetting.query.get(conf_id)
                if conf and not password:
                    password = decrypt_ldap_password(conf.password or conf.service_password)

            if not settings_data['server_ip'] or not settings_data['service_account']:
                flash("Заполните IP сервера и аккаунт")
                return redirect(url_for('settings'))

            if not password:
                flash("Результат LDAP: Ошибка - Пароль не может быть пустым")
                return redirect(url_for('settings'))

            try:
                # Проверка соединения
                from ldap3 import Server, Connection, ALL
                server = Server(settings_data['server_ip'], get_info=ALL, connect_timeout=5)
                # Simple Bind требует наличия пароля
                conn = Connection(server, user=settings_data['service_account'], password=password, auto_bind=True)
                
                # Если дошли сюда — соединение успешно. Сохраняем в БД.
                if not conf:
                    conf = LdapSetting()
                    db.session.add(conf)

                conf.connection_name = settings_data['connection_name']
                conf.domain_name = settings_data['domain_name']
                conf.server_ip = settings_data['server_ip']
                conf.base_dn = settings_data['base_dn']
                conf.service_account = settings_data['service_account']
                conf.password = encrypt_ldap_password(password)
                conf.admin_group_cn = settings_data['admin_group_cn']
                conf.admin_group_dn = settings_data['admin_group_dn']
                
                db.session.commit()
                flash("Результат LDAP: Соединение успешно. Настройки сохранены.")
                return redirect(url_for('settings'))

            except Exception as e:
                db.session.rollback()
                flash(f"Результат LDAP: Ошибка - {str(e)}")
                # Возвращаем шаблон с данными формы, чтобы не вводить заново
                return render_template('settings.html', user=user, config=config, logo_url=logo_url,
                                       configs=ldap_configs, mail_config=mail_config, 
                                       service_emails=service_emails, form_data=settings_data)

    # Финальный возврат для GET запроса
    return render_template('settings.html', 
                           config=config, 
                           logo_url=logo_url, 
                           user=user, 
                           configs=ldap_configs, 
                           mail_config=mail_config, 
                           service_emails=service_emails)

@app.route('/upload_logo', methods=['POST']) # Оставляем только POST
def upload_logo():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('Доступ запрещен')
        return redirect(url_for('index'))

    file = request.files.get('logo')
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.static_folder, 'uploads')
        os.makedirs(upload_path, exist_ok=True)
        
        file.save(os.path.join(upload_path, filename))
        
        config = SiteSettings.query.first()
        if not config:
            config = SiteSettings(namesite="Система заявок")
            db.session.add(config)
        
        config.logo_file = filename 
        db.session.commit()
        flash('Логотип обновлен!')
    else:
        flash('Файл не выбран')

    return redirect(url_for('settings'))

@app.context_processor
def inject_site_data():
    config = SiteSettings.query.first()
    logo_url = None
    site_name = "Система заявок"
    
    if config:
        site_name = config.namesite
        if config.logo_file:
            # Формируем путь к файлу логотипа
            logo_url = url_for('static', filename='uploads/' + config.logo_file)
    
    return dict(global_config=config, global_logo=logo_url, global_name=site_name)

@app.route('/settings/delete/<int:ldap_id>', methods=['POST'])
def delete_ldap(ldap_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    if user.role == 'admin':
        config = LdapSetting.query.get_or_404(ldap_id)
        db.session.delete(config)
        db.session.commit()
        flash('Конфигурация удалена')

    return redirect(url_for('settings'))


# Профиль и проверка на заполенность данных для обычных пользователей
@app.route('/profile', defaults={'user_id': None}, methods=['GET', 'POST'])
@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def profile(user_id=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    target_user = current_user
    if user_id is not None:
        if current_user.role != 'admin' and user_id != current_user.id:
            flash('Доступ запрещен')
            return redirect(url_for('index'))
        target_user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        building = request.form.get('building')
        room = request.form.get('room')
        phone = request.form.get('phone')
        mail = request.form.get('mail')
        computer_name = request.form.get('computer_name')
        notify_by_email = 'notify_by_email' in request.form
        
        if not full_name or not building or not room or not phone:
            flash('Заполните свой профиль')
        else:
            try:
                target_user.full_name = full_name
                target_user.building = building
                target_user.room = room
                target_user.phone = phone
                target_user.mail = mail
                target_user.computer_name = computer_name
                target_user.notify_by_email = notify_by_email
                db.session.commit()
                flash('Профиль успешно обновлен!')
                next_url = request.args.get('next')
                return redirect(next_url or url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash(f'Ошибка при сохранении: {e}')

    return render_template('profile.html', user=target_user)


# привести full_name к формату "Иванов И.И." для отображения в шапке и комментариях
@app.template_filter('format_fio')
def format_fio(full_name):
    if not full_name:
        return ""
    parts = full_name.split()
    if len(parts) == 1:
        return parts[0]
    elif len(parts) == 2:
        return f"{parts[0]} {parts[1][0]}."
    else:
        return f"{parts[0]} {parts[1][0]}.{parts[2][0]}."

if __name__ == '__main__':
    # На Windows Server 2016 запускаем на 0.0.0.0, чтобы XP могла подключиться по IP
    app.run(host='0.0.0.0', port=5000, debug=True)