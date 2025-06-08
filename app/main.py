from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import SQLModel, Session, select
from .database import engine, get_db
from .models import User, UserCreate, UserLogin, Token, TokenData
from .security import get_password_hash, verify_password, create_access_token

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Старая функция register из задания 3
@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
	existing_user = db.exec(select(User).where(User.username == user.username)).first()
	if existing_user:
		raise HTTPException(status_code=400, detail="Username already registered")
	
	hashed_password = get_password_hash(user.password)
	
	db_user = User(
		username=user.username,
		email=user.email,
		hashed_password=hashed_password
	)
	
	db.add(db_user)
	db.commit()
	db.refresh(db_user)
	return {"message": "User created successfully"}


# Обновленная функция login с JWT
@app.post("/login", response_model=Token)
async def login(user: UserLogin, db: Session = Depends(get_db)):
	db_user = db.exec(select(User).where(User.username == user.username)).first()
	
	if not db_user or not verify_password(user.password, db_user.hashed_password):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password"
		)
	
	access_token = create_access_token(data={"sub": db_user.username})
	return {"access_token": access_token, "token_type": "bearer"}


# Новый защищенный эндпоинт
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
	return {"token": token}