import os
from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2

def get_db_connection():
    return psycopg2.connect(
        host="localhost",
        port=5432,
        database="laba5rpp",
        user="postgres",
        password=os.getenv('DATABASE_PASSWORD')
    )


class User(UserMixin):
    # Делает из строки БД объект, который flask-login может использовать
    def __init__(self, user_id, email, password, name):
        self.id = user_id
        self.email = email
        self.password = password
        self.name = name

    @classmethod 
    def find_by_email(cls, email):
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, email, password, name FROM users WHERE email = %s;",
                    (email,)
                )
                row = cur.fetchone()
                if row:
                    # Преобразуем строку из БД в объект User 
                    return cls(row[0], row[1], row[2], row[3])
                return None
        finally:
            conn.close()

    # Вставляем нового пользователя в БД
    @classmethod
    def create(cls, name, email, password):
        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (name, email, password) VALUES (%s, %s, %s) RETURNING id;",
                    (name, email, password_hash)
                )
                new_id = cur.fetchone()[0]
            conn.commit()
            # Загружаем созданного пользователя из БД и возвращаем объект
            return cls.find_by_id(new_id)
        finally:
            conn.close()

    # Поиск пользователя по id
    @classmethod
    def find_by_id(cls, user_id):
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, email, password, name FROM users WHERE id = %s;",
                    (user_id,)
                )
                row = cur.fetchone()
                if row:
                    return cls(row[0], row[1], row[2], row[3])
                return None
        finally:
            conn.close()


# Объект Flask-приложения
app = Flask(__name__)
app.secret_key = "secret_for_laba"

# Настройка менеджера логина, интегрирует flask-login с приложением
login_manager = LoginManager()
login_manager.init_app(app)


# Функция, которую flask-login вызывает по id из сессии
@login_manager.user_loader
def load_user(user_id):
    return User.find_by_id(int(user_id))


# Корневая страница GET /
@app.route("/", methods=["GET"])
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("login_get"))
    return render_template("index.html", user=current_user)


# Страница входа GET /login
@app.route("/login", methods=["GET"])
def login_get():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("login.html", message=None)


# Авторизация POST /login
@app.route("/login", methods=["POST"])
def login_post():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    # Проверка
    if not email or not password:
        return render_template("login.html", message="Поля email и password обязательны для заполнения")

    # Поиск пользователя по email
    user = User.find_by_email(email)
    if user is None:
        return render_template("login.html", message="Пользователь с таким email не найден")

    if not check_password_hash(user.password, password):
        return render_template("login.html", message="Неправильный пароль")

    login_user(user)
    return redirect(url_for("index"))


# Страница регистрации GET /signup
@app.route("/signup", methods=["GET"])
def signup_get():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("signup.html", message=None)


# Регистрация POST /signup
@app.route("/signup", methods=["POST"])
def signup_post():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    # Проверка
    if not name or not email or not password:
        return render_template("signup.html", message="Все поля обязательны для заполнения")

    # Проверяем, есть ли уже пользователь с таким email
    user = User.find_by_email(email)
    if user is not None:
        return render_template("signup.html", message="Пользователь с таким email уже существует")

    # Создаём пользователя и перенаправляем на страницу входа
    User.create(name, email, password)
    return redirect(url_for("login_get"))


# Выход GET /logout
@app.route("/logout", methods=["GET"])
def logout():
    if current_user.is_authenticated:
        # Удаляем информацию о пользователе из сессии (current_user становится анонимным)
        logout_user()
    # После выхода - на страницу входа
    return redirect(url_for("login_get"))


if __name__ == "__main__":
    app.run(debug=True)