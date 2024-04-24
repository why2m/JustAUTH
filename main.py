from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette import status

from utils import create_jwt_token

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    username: str
    hashed_pwd: str


fake_user_list: list[User] = [
    User(username="admin", hashed_pwd="12345"),
    User(username="dev", hashed_pwd="123123"),
    User(username="read", hashed_pwd="54321"),
]


@app.post("/register")
def register_user(username: str, pwd: str):
    hashed_pwd = pwd_context.hash(pwd)
    new_user: User = User(username=username, hashed_pwd=hashed_pwd)
    fake_user_list.append(new_user)
    return new_user


@app.post("/token")
def auth_user(username: str, pwd: str):
    user = next((user for user in fake_user_list if user.username == username), None)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or pwd.")

    is_pwd_correct = pwd_context.verify(pwd, user.hashed_pwd)

    if not is_pwd_correct:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or pwd.")

    jwt_token = create_jwt_token({"sub": user.username})

    return {"access_token": jwt_token, "token_type": "bearer"}


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}
