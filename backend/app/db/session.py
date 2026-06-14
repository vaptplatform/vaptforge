"""
Database Session Management - Async SQLAlchemy setup
"""
import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models.models import Base

logger = logging.getLogger("vapt.db")

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_recycle=3600,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created/verified")
    await _seed_initial_data()


async def _seed_initial_data() -> None:
    from app.models.models import Organization, User, UserRole
    from app.core.security import hash_password
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Organization).where(Organization.slug == "default")
        )
        org = result.scalar_one_or_none()

        if not org:
            org = Organization(
                name="Default Organization",
                slug="default",
                plan="enterprise",
            )
            session.add(org)
            await session.flush()

            admin = User(
                org_id=org.id,
                email="vaptplatform@gmail.com",
                full_name="Platform Admin",
                password_hash=hash_password("ChangeMe!2024"),
                role=UserRole.ADMIN,
            )
            session.add(admin)
            await session.commit()

            logger.info("Seeded default org and admin user: vaptplatform@gmail.com / ChangeMe!2024")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()