from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    def _validate_email(cls, v: str) -> str:
        accounts_validators.validate_email(v)
        return v


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def _validate_password(cls, v: str) -> str:
        accounts_validators.validate_password_strength(v)
        return v


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(UserBase):
    token: str


class UserLoginRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def _validate_password_login(cls, v: str) -> str:
        if not v:
            raise ValueError("Password must not be empty")
        return v


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {"from_attributes": True}


class TokenRefreshResponseSchema(UserLoginResponseSchema):
    pass


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(
    UserRegistrationRequestSchema, UserActivationRequestSchema
):
    pass
