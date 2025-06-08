from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from .database import get_db
from .models import User
from .schemas import TokenData
from sqlalchemy.ext.asyncio import AsyncSession

# Конфигурация JWT
SECRET_KEY = "your-secret-key-change-me-in-production"  # Используйте: openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Настройки для паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


class Token(BaseModel):
	access_token: str
	token_type: str


def verify_password(plain_password: str, hashed_password: str):
	"""Проверка пароля"""
	return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str):
	"""Генерация хеша пароля"""
	return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
	"""Создание JWT токена"""
	to_encode = data.copy()
	if expires_delta:
		expire = datetime.utcnow() + expires_delta
	else:
		expire = datetime.utcnow() + timedelta(minutes=15)
	to_encode.update({"exp": expire})
	return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def authenticate_user(db: AsyncSession, username: str, password: str):
	"""Аутентификация пользователя"""
	user = await get_user(db, username)
	if not user:
		return False
	if not verify_password(password, user.hashed_password):
		return False
	return user


async def get_user(db: AsyncSession, username: str):
	"""Получение пользователя из БД"""
	result = await db.execute(select(User).where(User.username == username))
	return result.scalars().first()


async def get_current_user(
		token: str = Depends(oauth2_scheme),
		db: AsyncSession = Depends(get_db)
):
	"""Получение текущего пользователя из JWT токена"""
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception
		token_data = TokenData(username=username)
	except JWTError:
		raise credentials_exception
	
	user = await get_user(db, username=token_data.username)
	if user is None:
		raise credentials_exception
	return user