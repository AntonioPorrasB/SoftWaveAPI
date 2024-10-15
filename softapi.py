import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from passlib.context import CryptContext
from pydantic import BaseModel
import logging
from fastapi.middleware.cors import CORSMiddleware

# Configuración de la base de datos
DATABASE_URL = "postgresql://postgres:R4kav3liYT@localhost/softwave"
#DATABASE_URL = "postgresql://softwavedb_user:NPkYyKEeti5wFmvk9r3jXH7Xg93f2pOq@dpg-cs6vvtl6l47c738uam40-a.frankfurt-postgres.render.com/softwavedb"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Modelo de usuario
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class UserRegister(BaseModel):
    name: str
    email: str
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    username: str

class UserUpdate(BaseModel):
    name: str = None
    email: str = None
    password: str = None
    
class LoginRequest(BaseModel):
    username: str
    password: str

# Crear tablas en la base de datos
Base.metadata.create_all(bind=engine)

# Inicializar FastAPI
app = FastAPI()
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app.title = "SoftWave API"
app.version = "1.0.0"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "https://datawaveapi.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Función para encriptar contraseñas
def get_password_hash(password):
    return bcrypt_context.hash(password)

# Función para verificar contraseñas
def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)

# Función para obtener el usuario a partir del nombre de usuario
def get_user_by_username(username: str, db: Session):
    return db.query(User).filter(User.username == username).first()

# Dependencia para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/", tags=['Home'])
async def read_root():
    return {"message": "Welcome to the SoftWave API!"}

# Ruta para registrar un nuevo usuario
@app.post("/register", response_model=UserResponse)
def register(user: UserRegister, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    new_user = User(name=user.name, email=user.email, username=user.username, hashed_password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse(id=new_user.id, name=new_user.name, email=new_user.email, username=new_user.username)

# Ruta para iniciar sesión
@app.post("/login", response_model=UserResponse, tags=['Sesion'])
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()

    # Si el usuario no existe
    if not user:
        logger.warning(f"Intento de inicio de sesión fallido para el usuario: {request.username} - Usuario no encontrado")
        raise HTTPException(status_code=400, detail="El usuario no existe")

    # Si la contraseña es incorrecta
    if not verify_password(request.password, user.hashed_password):
        logger.warning(f"Intento de inicio de sesión fallido para el usuario: {request.username} - Contraseña incorrecta")
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        username=user.username
    )

@app.put("/update/{username}", tags=['Sesion'])
def update_user(username: str, updated_user: UserUpdate, db: Session = Depends(get_db)):
    user = get_user_by_username(username, db)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if updated_user.email:
        user.email = updated_user.email
    if updated_user.password:
        user.hashed_password = get_password_hash(updated_user.password)
    if updated_user.name:
        user.name = updated_user.name

    db.commit()
    return {"detail": "Usuario actualizado exitosamente"}

@app.delete("/delete/{username}", tags=['Sesion'])
def delete_user(username: str, db: Session = Depends(get_db)):
    user = get_user_by_username(username, db)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(user)
    db.commit()
    return {"detail": "Usuario eliminado exitosamente"}

# Iniciar la aplicación
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
