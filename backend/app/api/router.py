from fastapi import APIRouter

from app.api.routes import assistant, campaigns, iocs, operations, reports, rules, stats, techniques

api_router = APIRouter()
api_router.include_router(iocs.router)
api_router.include_router(stats.router)
api_router.include_router(campaigns.router)
api_router.include_router(techniques.router)
api_router.include_router(rules.router)
api_router.include_router(reports.router)
api_router.include_router(assistant.router)
api_router.include_router(operations.router)
