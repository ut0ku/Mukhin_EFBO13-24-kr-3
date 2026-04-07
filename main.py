from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from pydantic_settings import BaseSettings
import secrets
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from database import get_db_connection

# --- Конфигурация окружения ---
class Settings(BaseSettings):
    MODE: str = "DEV"
    DOCS_USER: str = "admin"
    DOCS_PASSWORD: str = "secret"

    class Config:
        env_file = ".env"

settings = Settings()

if settings.MODE not in ("DEV", "PROD"):
    raise ValueError(f"Недопустимое значение MODE: {settings.MODE}. Ожидалось 'DEV' или 'PROD'")

# Отключаем стандартные эндпоинты документации, чтобы переопределить их или скрыть (в PROD)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()

# --- Настройка Rate Limiter (ограничение запросов) ---
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- Раздел: Защита документации (в DEV-режиме) ---
def auth_docs(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, settings.DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, settings.DOCS_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials for docs",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

if settings.MODE == "DEV":
    
    # Кастомный защищенный маршрут для Swagger UI
    @app.get("/docs", include_in_schema=False)
    def custom_swagger_ui_html(username: str = Depends(auth_docs)):
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=app.title + " - Swagger UI",
            oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        )

    # Кастомный защищенный маршрут для схемы OpenAPI
    @app.get("/openapi.json", include_in_schema=False)
    def get_openapi_endpoint(username: str = Depends(auth_docs)):
        return app.openapi()


# --- 1. Создание моделей данных ---
class User(BaseModel):
    username: str
    password: str

class TodoCreate(BaseModel):
    title: str
    description: str

class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool

class TodoResponse(BaseModel):
    id: int
    title: str
    description: str
    completed: bool

# --- 2. Настройка PassLib ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fake_users_db = {}

# --- 3. Зависимость аутентификации API ---
def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    user_db = None
    # Для защиты от timing attacks перебираем всех пользователей и сравниваем через secrets.compare_digest
    for db_username, user_info in fake_users_db.items():
        if secrets.compare_digest(credentials.username, db_username):
            user_db = user_info
            break
            
    if not user_db or not pwd_context.verify(credentials.password, user_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user_db

# --- 4. Реализация маршрутов /register и /login ---
import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = "my_super_secret_jwt_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security_bearer = HTTPBearer()

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

from database import get_db_connection

@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")
def register(request: Request, user: User):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", 
            (user.username, user.password)
        )
        conn.commit()
    finally:
        conn.close()
    return {"message": "User registered successfully!"}


# Обновленный /login
@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user: User):
    user_db = None
    # Ищем пользователя (с защитой от тайм-атак)
    for db_username, user_info in fake_users_db.items():
        if secrets.compare_digest(user.username, db_username):
            user_db = user_info
            break
            
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Проверяем пароль
    if not pwd_context.verify(user.password, user_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed",
        )
    
    # Если данные верные, генерируем JWT токен
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": user.username, "role": user_db.role, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": encoded_jwt, "token_type": "bearer"}


# --- Управление доступом на основе ролей (RBAC) ---
from typing import List

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, jwt_payload: dict = Depends(verify_jwt_token)):
        user_role = jwt_payload.get("role")
        if not user_role or user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {self.allowed_roles}"
            )
        return jwt_payload

# Экземпляры валидаторов для разных наборов ролей
allow_admin = RoleChecker(["admin"])
allow_admin_user = RoleChecker(["admin", "user"])
allow_all_roles = RoleChecker(["admin", "user", "guest"])

# Пример "базы данных" элементов
fake_items_db = [{"name": "Item 1"}]

@app.get("/protected_resource")
def protected_resource(jwt_payload: dict = Depends(allow_admin_user)):
    return {
        "message": "Access granted to protected resource",
        "username": jwt_payload.get("sub"),
        "role": jwt_payload.get("role")
    }

# Для админа: создание
@app.post("/items", dependencies=[Depends(allow_admin)])
def create_item(item: dict):
    fake_items_db.append(item)
    return {"message": "Item created successfully"}

# Для всех (в т.ч. гостя): только чтение
@app.get("/items", dependencies=[Depends(allow_all_roles)])
def read_items():
    return {"items": fake_items_db}

# Для админа и пользователя: обновление (чтение + запись для существующих)
@app.put("/items/{item_id}", dependencies=[Depends(allow_admin_user)])
def update_item(item_id: int, item: dict):
    if item_id < len(fake_items_db):
        fake_items_db[item_id] = item
        return {"message": "Item updated successfully"}
    raise HTTPException(status_code=404, detail="Item not found")

# Только для админа: удаление 
@app.delete("/items/{item_id}", dependencies=[Depends(allow_admin)])
def delete_item(item_id: int):
    if item_id < len(fake_items_db):
        fake_items_db.pop(item_id)
        return {"message": "Item deleted successfully"}
    raise HTTPException(status_code=404, detail="Item not found")

# --- 5. CRUD эндпоинты для Todo ---

@app.post("/todos", status_code=status.HTTP_201_CREATED, response_model=TodoResponse)
def create_todo(todo: TodoCreate):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO todos (title, description, completed) VALUES (?, ?, ?)",
            (todo.title, todo.description, False)
        )
        todo_id = cursor.lastrowid
        conn.commit()
        return {"id": todo_id, "title": todo.title, "description": todo.description, "completed": False}
    finally:
        conn.close()

@app.get("/todos/{todo_id}", response_model=TodoResponse)
def read_todo(todo_id: int):
    conn = get_db_connection()
    try:
        todo = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
        if todo is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")
        return {"id": todo["id"], "title": todo["title"], "description": todo["description"], "completed": bool(todo["completed"])}
    finally:
        conn.close()

@app.put("/todos/{todo_id}", response_model=TodoResponse)
def update_todo(todo_id: int, todo: TodoUpdate):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")
            
        cursor.execute(
            "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
            (todo.title, todo.description, todo.completed, todo_id)
        )
        conn.commit()
        return {"id": todo_id, "title": todo.title, "description": todo.description, "completed": todo.completed}
    finally:
        conn.close()

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        if cursor.fetchone() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")
            
        cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()
        return {"message": "Todo deleted successfully!"}
    finally:
        conn.close()

