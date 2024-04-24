from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette import status

from utils import create_jwt_token, verify_jwt_token

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    username: str
    hashed_pwd: str


fake_user_list: list[User] = [
    User(username="admin", hashed_pwd="12345"),
]


@app.post("/register")
def register_user(username: str, pwd: str):
    user = next((user for user in fake_user_list if user.username == username), None)

    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Username '{username}' is already taken")

    hashed_pwd = pwd_context.hash(pwd)
    new_user: User = User(username=username, hashed_pwd=hashed_pwd)
    fake_user_list.append(new_user)
    return new_user


@app.post("/token")
def auth_user(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    pwd = form_data.password
    user = next((user for user in fake_user_list if user.username == username), None)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or pwd.")

    is_pwd_correct = pwd_context.verify(pwd, user.hashed_pwd)

    if not is_pwd_correct:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect username or pwd.")

    jwt_token = create_jwt_token({"sub": user.username})
    return {
        "access_token": jwt_token,
        "token_type": "bearer",
    }


def get_current_user(token: str = Depends(oauth2_scheme)):
    decoded_data = verify_jwt_token(token)
    if not decoded_data:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = next((user for user in fake_user_list if user.username == decoded_data["sub"]), None)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    return user


@app.get("/usernames")
async def root(current_user: User = Depends(get_current_user)):
    return [user.username for user in fake_user_list]


@app.get("/users")
def get_all_users_data() -> list[User]:
    return fake_user_list
