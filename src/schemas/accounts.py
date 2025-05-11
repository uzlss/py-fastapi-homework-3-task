from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    def _validate_email(cls, v: str) -> str:
        # this should raise a ValueError if the email is invalid/exists/etc.
        accounts_validators.validate_email(v)
        return v

class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def _validate_password(cls, v: str) -> str:
        # this should raise a ValueError if the password is too weak
        accounts_validators.validate_password_strength(v)
        return v

class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {
        "from_attributes": True
    }
