from sqlmodel import create_engine, Session

DATABASE_URL = "postgresql+psycopg2://postgres:Aa1234@localhost:5432/postgres"

engine = create_engine(DATABASE_URL)

def get_db():
    with Session(engine) as session:
        yield session