import os
import shutil
import tempfile
import json
import asyncio
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse

import anthropic
from anthropic import AnthropicBedrockMantle
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from git import Repo
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

AWS_REGION = os.getenv("AWS_REGION_NAME") or os.getenv("AWS_REGION")
if not AWS_REGION:
    raise ValueError("Missing required environment variable: AWS_REGION_NAME (or AWS_REGION)")

# AWS access keys are optional: boto3's default credential chain
# (env vars, ~/.aws/credentials, IAM role) is used when they are not set.
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-sonnet-5")
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", str(200 * 1024)))
MAX_ANALYSIS_TOKENS = 8192

SCAN_EXTENSIONS = (
    '.py', '.js', '.jsx', '.java', '.rb', '.php', '.go', '.ts', '.tsx',
    '.c', '.cpp', '.cs', '.kt', '.swift', '.html', '.css',
)
SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', 'dist', 'build', '.next',
    '__pycache__', '.venv', 'venv', 'target', 'coverage',
}

app = FastAPI(title="Code Security Scanner API")

allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bedrock_client = AnthropicBedrockMantle(aws_region=AWS_REGION)

SYSTEM_PROMPT = """You are a security expert analyzing code for vulnerabilities. For each vulnerability found, provide:
1. File name
2. Line number (if applicable)
3. Description of the vulnerability
4. Severity level (High, Medium, Low)
5. Recommended fix

If no vulnerabilities are found, simply state "No vulnerabilities found in this file."
"""


class RepositoryScanRequest(BaseModel):
    repository_url: str
    access_token: Optional[str] = None


def redact_token(text: str, token: Optional[str]) -> str:
    """Prevent the access token from leaking into log or SSE error output."""
    if token:
        return text.replace(token, "***")
    return text


def construct_authenticated_url(repo_url: str, token: Optional[str]) -> str:
    parsed_url = urlparse(repo_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        raise ValueError("Repository URL must be a valid http(s) URL.")

    if not token:
        return repo_url

    host = parsed_url.netloc.lower()
    if "github.com" in host:
        authenticated_netloc = f"x-access-token:{token}@{parsed_url.netloc}"
    elif "bitbucket.org" in host:
        authenticated_netloc = f"x-token-auth:{token}@{parsed_url.netloc}"
    else:
        authenticated_netloc = f"{token}@{parsed_url.netloc}"

    return urlunparse((
        parsed_url.scheme, authenticated_netloc, parsed_url.path,
        parsed_url.params, parsed_url.query, parsed_url.fragment,
    ))


def analyze_code(relative_file_path: str, content: str) -> str:
    response = bedrock_client.messages.create(
        model=MODEL_ID,
        max_tokens=MAX_ANALYSIS_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": (
                "Analyze the following code for security vulnerabilities:\n\n"
                f"File: {relative_file_path}\n"
                f"Code:\n```\n{content}\n```"
            ),
        }],
    )
    if response.stop_reason == "refusal":
        return "Analysis was declined by the model's safety system for this file."
    return "".join(block.text for block in response.content if block.type == "text")


def iter_scannable_files(root_dir: str):
    for subdir, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file_name in files:
            if file_name.endswith(SCAN_EXTENSIONS):
                yield os.path.join(subdir, file_name)


def sse_event(event_type: str, payload) -> str:
    return f"data: {json.dumps({'type': event_type, 'payload': payload})}\n\n"


async def stream_scan_events(repo_url: str, access_token: Optional[str]):
    temp_dir = None
    try:
        authenticated_repo_url = construct_authenticated_url(repo_url, access_token)

        display_url = repo_url if not access_token else "provided URL (token redacted)"
        yield sse_event('status', f'Cloning repository from {display_url}...')

        temp_dir = tempfile.mkdtemp()
        # Shallow clone in a worker thread so the event loop is not blocked.
        await asyncio.to_thread(Repo.clone_from, authenticated_repo_url, temp_dir, depth=1)
        yield sse_event('status', 'Repository cloned successfully.')

        vulnerabilities_found_overall = False
        scanned_files_count = 0

        for file_path in iter_scannable_files(temp_dir):
            relative_file_path = os.path.relpath(file_path, temp_dir)
            yield sse_event('progress', f'Scanning file: {relative_file_path}')
            scanned_files_count += 1

            try:
                if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
                    yield sse_event('info', f'Skipping large file (> {MAX_FILE_SIZE_BYTES // 1024}KB): {relative_file_path}')
                    continue

                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                if not content.strip():
                    yield sse_event('info', f'Skipping empty file: {relative_file_path}')
                    continue

                analysis_result = await asyncio.to_thread(analyze_code, relative_file_path, content)

                if analysis_result and "No vulnerabilities found" not in analysis_result:
                    vulnerabilities_found_overall = True
                    yield sse_event('vulnerability', {'file': relative_file_path, 'analysis': analysis_result})
                else:
                    yield sse_event('info', f'No vulnerabilities found in: {relative_file_path}')

            except anthropic.RateLimitError:
                yield sse_event('error', f'Rate limited while analyzing {relative_file_path}. Waiting before retrying next file...')
                await asyncio.sleep(10)
            except anthropic.APIStatusError as e:
                yield sse_event('error', f'Model API error ({e.status_code}) while analyzing {relative_file_path}.')
            except Exception as e:
                error_message = redact_token(f"Error processing file {relative_file_path}: {e}", access_token)
                print(error_message)
                yield sse_event('error', error_message)

        if scanned_files_count == 0:
            yield sse_event('status', 'No supported files found to scan in the repository.')
        elif not vulnerabilities_found_overall:
            yield sse_event('status', 'Scan complete. No vulnerabilities found in supported files.')
        else:
            yield sse_event('status', 'Scan complete. Vulnerabilities were found.')

    except Exception as e:
        error_detail = redact_token(f"An unexpected error occurred during scanning: {e}", access_token)
        print(error_detail)
        yield sse_event('critical_error', error_detail)
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            yield sse_event('status', 'Cleaned up temporary files.')

        yield sse_event('done', 'Process finished.')


@app.get("/health")
async def health_check():
    return {"status": "ok", "model": MODEL_ID}


@app.post("/scan_repository")
async def scan_repository_endpoint(request: RepositoryScanRequest):
    return StreamingResponse(
        stream_scan_events(request.repository_url, request.access_token),
        media_type="text/event-stream",
    )

# To run the app (from the 'backend' directory):
# uvicorn main:app --reload
