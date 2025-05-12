from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

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
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    UserLoginRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

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
    try:
        if await db.scalar(
            select(UserModel).where(UserModel.email == payload.email)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {payload.email} already exists.",
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
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

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
    now = datetime.utcnow()
    if not token_rec or token_rec.expires_at < now:
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
        user = await db.scalar(
            select(UserModel).where(UserModel.email == data.email)
        )
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
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == data.email)
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )
        token_entry = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == data.token,
            )
        )
        now = datetime.utcnow()
        if not token_entry or token_entry.expires_at < now:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )
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
    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == data.email)
        )
        if not user or not verify_password(
            data.password, user._hashed_password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
        new_refresh = RefreshTokenModel(
            token=refresh_token,
            user_id=user.id,
            expires_at=datetime.utcnow()
            + timedelta(days=settings.LOGIN_TIME_DAYS),
        )
        db.add(new_refresh)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    token_rec = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    )
    now = datetime.utcnow()
    if not token_rec:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    if token_rec.expires_at < now:
        await db.execute(
            delete(RefreshTokenModel).where(
                RefreshTokenModel.id == token_rec.id
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    user = await db.scalar(
        select(UserModel).where(UserModel.id == token_rec.user_id)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    new_access = jwt_manager.create_access_token({"user_id": user.id})
    new_refresh = jwt_manager.create_refresh_token({"user_id": user.id})
    new_rec = RefreshTokenModel(
        token=new_refresh,
        user_id=user.id,
        expires_at=now + timedelta(days=settings.LOGIN_TIME_DAYS),
    )
    try:
        await db.execute(
            delete(RefreshTokenModel).where(
                RefreshTokenModel.id == token_rec.id
            )
        )
        db.add(new_rec)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while rotating refresh token.",
        )
    return TokenRefreshResponseSchema(
        access_token=new_access,
        refresh_token=new_refresh,
        token_type="bearer",
    )
