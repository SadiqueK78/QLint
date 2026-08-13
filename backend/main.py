import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import database
from routers.admin_router import router as admin_router
from routers.auth_router import router as auth_router
from routers.benchmark_router import router as benchmark_router
from routers.explain_router import router as explain_router
from routers.hndl_router import router as hndl_router
from routers.oauth_router import router as oauth_router
from routers.patch_router import router as patch_router
from routers.pr_router import router as pr_router
from routers.scan_router import router as scan_router
from routers.user_router import router as user_router

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SERVICE_NAME = "PQC Migration Scanner"

# Browser origins allowed to call this API. 5174 is the port vite.config.js
# pins; 5173 is Vite's default, kept so an unpinned dev server also works.
ALLOWED_ORIGINS = ["http://localhost:5173", "http://localhost:5174"]

# A deployed frontend is served from somewhere else, and it cannot be covered
# by a "*" wildcard: allow_credentials=True below rules that out, so the origin
# has to be listed explicitly. Reusing the variable oauth_router already reads
# means one setting moves both the CORS allowance and the OAuth redirect.
#
# rstrip("/") because the browser's Origin header never carries a trailing
# slash -- FRONTEND_URL="https://app.example.com/" would otherwise compare
# unequal to "https://app.example.com" and silently fail every request.
FRONTEND_URL = os.getenv("FRONTEND_URL", "").rstrip("/")
if FRONTEND_URL and FRONTEND_URL not in ALLOWED_ORIGINS:
    ALLOWED_ORIGINS.append(FRONTEND_URL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Shared async client for GitHub API calls, authenticated if a token is set.
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    app.state.github = httpx.AsyncClient(
        base_url="https://api.github.com", headers=headers, timeout=30.0
    )
    # Shared async client for OpenRouter (AI explanation) calls. Auth header
    # is per-request in ai_explainer.py, not set here.
    app.state.openrouter = httpx.AsyncClient(timeout=30.0)

    database.connect()
    # A missing database must not stop the server: anonymous scanning still
    # works, and the auth/history routes report 503 until Mongo comes back.
    app.state.db_ready = await database.ping()
    if app.state.db_ready:
        await database.create_indexes()
    else:
        print(
            "WARNING: could not reach MongoDB at "
            f"{database.MONGODB_URI}. Accounts, history, and scan caching "
            "are disabled until it is running."
        )

    yield

    await app.state.github.aclose()
    await app.state.openrouter.aclose()
    await database.close()


app = FastAPI(title=SERVICE_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, tags=["auth"])
app.include_router(oauth_router, tags=["auth"])
app.include_router(scan_router, tags=["scan"])
app.include_router(explain_router, tags=["scan"])
app.include_router(patch_router, tags=["scan"])
# The one router that writes to a user's repository. Mounted like any other,
# but reachable only with the separate write-scope token oauth_router stores.
app.include_router(pr_router, tags=["scan"])
app.include_router(user_router, tags=["user"])
app.include_router(admin_router, tags=["admin"])
app.include_router(hndl_router, tags=["hndl"])
# Needs the liboqs native library. benchmark_router mounts either way and
# answers 503 where liboqs is absent, so a Windows-native dev run still boots.
app.include_router(benchmark_router, tags=["benchmark"])


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": SERVICE_NAME,
        "database": "connected" if await database.ping() else "unavailable",
    }
