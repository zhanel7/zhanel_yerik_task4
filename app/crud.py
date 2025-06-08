from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status
import logging
from .models import User
from .auth import get_password_hash

logger = logging.getLogger(__name__)


async def get_user(db: AsyncSession, username: str):
	"""Получение пользователя по username"""
	try:
		result = await db.execute(select(User).where(User.username == username))
		return result.scalars().first()
	except SQLAlchemyError as e:
		logger.error(f"Database error in get_user: {str(e)}")
		raise HTTPException(
			status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
			detail="Database error while fetching user"
		)


async def get_user_by_email(db: AsyncSession, email: str):
	"""Получение пользователя по email"""
	try:
		result = await db.execute(select(User).where(User.email == email))
		return result.scalars().first()
	except SQLAlchemyError as e:
		logger.error(f"Database error in get_user_by_email: {str(e)}")
		raise HTTPException(
			status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
			detail="Database error while fetching user by email"
		)


async def create_user(db: AsyncSession, user_data: dict):
	"""Создание нового пользователя"""
	try:
		hashed_password = get_password_hash(user_data["password"])
		db_user = User(
			username=user_data["username"],
			email=user_data["email"],
			hashed_password=hashed_password,
			is_active=True
		)
		db.add(db_user)
		await db.commit()
		await db.refresh(db_user)
		return db_user
	except SQLAlchemyError as e:
		await db.rollback()
		logger.error(f"Database error in create_user: {str(e)}")
		raise HTTPException(
			status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
			detail="Database error while creating user"
		)


async def update_user(db: AsyncSession, username: str, update_data: dict):
	"""Обновление данных пользователя"""
	try:
		user = await get_user(db, username)
		if not user:
			return None
		
		for key, value in update_data.items():
			if key == "password":
				setattr(user, "hashed_password", get_password_hash(value))
			elif hasattr(user, key):
				setattr(user, key, value)
		
		await db.commit()
		await db.refresh(user)
		return user
	except SQLAlchemyError as e:
		await db.rollback()
		logger.error(f"Database error in update_user: {str(e)}")
		raise HTTPException(
			status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
			detail="Database error while updating user"
		)


async def deactivate_user(db: AsyncSession, username: str):
	"""Деактивация пользователя"""
	try:
		user = await get_user(db, username)
		if not user:
			return False
		
		user.is_active = False
		await db.commit()
		return True
	except SQLAlchemyError as e:
		await db.rollback()
		logger.error(f"Database error in deactivate_user: {str(e)}")
		raise HTTPException(
			status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
			detail="Database error while deactivating user"
		)