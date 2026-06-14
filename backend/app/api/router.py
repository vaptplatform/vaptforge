"""API Router — registers all sub-routers."""
from fastapi import APIRouter
from app.api import auth, scans, findings, reports, domains, users, alerts, audit, websocket_routes
from app.api import scanners

api_router = APIRouter()

api_router.include_router(auth.router,             prefix="/auth",        tags=["Auth"])
api_router.include_router(scans.router,            prefix="/scans",       tags=["Scans"])
api_router.include_router(findings.router,         prefix="/findings",    tags=["Findings"])
api_router.include_router(reports.router,          prefix="/reports",     tags=["Reports"])
api_router.include_router(domains.router,          prefix="/domains",     tags=["Domains"])
api_router.include_router(users.router,            prefix="/users",       tags=["Users"])
api_router.include_router(alerts.router,           prefix="/alerts",      tags=["Alerts"])
api_router.include_router(audit.router,            prefix="/audit",       tags=["Audit"])
api_router.include_router(websocket_routes.router, prefix="/ws",          tags=["WebSocket"])
api_router.include_router(scanners.router,         prefix="/scanners",    tags=["SAST/DAST"])
