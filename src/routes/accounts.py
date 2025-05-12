from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def register_user(
    payload: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    async with db.begin():
        existing = await db.scalar(
            select(UserModel).where(UserModel.email == payload.email)
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with email {payload.email} already exists.",
            )

        default_group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        )

        new_user = UserModel(
            email=payload.email,
            _hashed_password=hash_password(payload.password),
            group=default_group,
        )
        db.add(new_user)
        await db.flush()

        db.add(ActivationTokenModel(user_id=new_user.id))

    await db.refresh(new_user)
    return new_user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(ActivationTokenModel.user)
        .where(
            UserModel.email == payload.email,
            ActivationTokenModel.token == payload.token,
        )
    )
    token_rec = result.scalar_one_or_none()
    if not token_rec or token_rec.expires_at.replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        if token_rec:
            await db.execute(
                delete(ActivationTokenModel).where(
                    ActivationTokenModel.id == token_rec.id
                )
            )
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token_rec.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    try:
        user.is_active = True
        await db.execute(
            delete(ActivationTokenModel).where(
                ActivationTokenModel.id == token_rec.id
            )
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the account.",
        )

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = result.scalar_one_or_none()
        if user and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)
            await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing password reset request.",
        )
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/password-reset/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token or email.",
            )
        token_q = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == data.token,
        )
        token_entry = (await db.execute(token_q)).scalar_one_or_none()
        # Validate existence and expiration
        if not token_entry or token_entry.expires_at.replace(
            tzinfo=timezone.utc
        ) < datetime.now(timezone.utc):
            if token_entry:
                await db.execute(
                    delete(PasswordResetTokenModel).where(
                        PasswordResetTokenModel.id == token_entry.id
                    )
                )
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token or email.",
            )
        # Hash new password and delete token
        user._hashed_password = hash_password(data.password)
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.id == token_entry.id
            )
        )
        await db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
    return MessageResponseSchema(
        message="Your password has been reset successfully."
    )
