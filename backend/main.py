import os
import shutil
import tempfile
import json
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import boto3
from git import Repo
from dotenv import load_dotenv
from typing import Optional # Added for Optional access_token
from urllib.parse import urlparse, urlunparse # Added for URL manipulation
from pathlib import Path

# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

# Validate required environment variables
required_env_vars = ['AWS_REGION_NAME', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

app = FastAPI()

# CORS Middleware
origins = [
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Kept as ["*"] for now to avoid blocking PAT testing due to potential CORS issues. Will remind to restrict later.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bedrock_runtime = boto3.client(
    service_name='bedrock-runtime',
    region_name=os.getenv("AWS_REGION_NAME"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    endpoint_url=f"https://bedrock-runtime.{os.getenv('AWS_REGION_NAME')}.amazonaws.com"
)

MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"

class RepositoryScanRequest(BaseModel):
    repository_url: str
    access_token: Optional[str] = None # Added PAT field

def construct_authenticated_url(repo_url: str, token: Optional[str]) -> str:
    if not token:
        return repo_url

    parsed_url = urlparse(repo_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        # Not a valid URL to easily inject token, return original or raise error
        # For simplicity, returning original; robust error handling could be added
        return repo_url

    # Ensure path starts with a slash if it's not empty
    path = parsed_url.path
    if path and not path.startswith('/'):
        path = '/' + path
    
    if "github.com" in parsed_url.netloc.lower():
        # For GitHub, format is https://<token>@github.com/owner/repo.git
        # Or, some prefer https://x-access-token:<token>@github.com/...
        # Using the simpler <token>@ form for now.
        authenticated_netloc = f"{token}@{parsed_url.netloc}"
    elif "bitbucket.org" in parsed_url.netloc.lower():
        # For Bitbucket, format is https://x-token-auth:<token>@bitbucket.org/owner/repo.git
        authenticated_netloc = f"x-token-auth:{token}@{parsed_url.netloc}"
    else:
        # Generic approach for other providers, may need adjustment
        # This assumes the token can be used as a username.
        authenticated_netloc = f"{token}@{parsed_url.netloc}"
        
    return urlunparse((parsed_url.scheme, authenticated_netloc, path, parsed_url.params, parsed_url.query, parsed_url.fragment))


async def stream_scan_events(repo_url: str, access_token: Optional[str]): # Added access_token parameter
    temp_dir = None
    try:
        authenticated_repo_url = construct_authenticated_url(repo_url, access_token)
        
        display_url = repo_url if not access_token else "provided URL with token"
        yield f"data: {json.dumps({'type': 'status', 'payload': f'Cloning repository from {display_url}...'})}\n\n"
        await asyncio.sleep(0.1)

        temp_dir = tempfile.mkdtemp()
        Repo.clone_from(authenticated_repo_url, temp_dir) # Use authenticated URL
        yield f"data: {json.dumps({'type': 'status', 'payload': 'Repository cloned successfully.'})}\n\n"
        await asyncio.sleep(0.1)

        vulnerabilities_found_overall = False
        scanned_files_count = 0

        for subdir, dirs, files in os.walk(temp_dir):
            for file_name in files:
                if file_name.endswith(('.py', '.js', '.java', '.rb', '.php', '.go', '.ts', '.tsx', '.html', '.css')):
                    file_path = os.path.join(subdir, file_name)
                    relative_file_path = os.path.relpath(file_path, temp_dir)
                    
                    yield f"data: {json.dumps({'type': 'progress', 'payload': f'Scanning file: {relative_file_path}'})}\n\n"
                    await asyncio.sleep(0.1)
                    scanned_files_count += 1

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if not content.strip():
                            yield f"data: {json.dumps({'type': 'info', 'payload': f'Skipping empty file: {relative_file_path}'})}\n\n"
                            await asyncio.sleep(0.1)
                            continue
                        
                        prompt = f"""<|im_start|>system
You are a security expert analyzing code for vulnerabilities. For each vulnerability found, provide:
1. File name
2. Line number (if applicable)
3. Description of the vulnerability
4. Severity level (High, Medium, Low)
5. Recommended fix

If no vulnerabilities are found, simply state "No vulnerabilities found in this file."
<|im_end|>

<|im_start|>user
Analyze the following code for security vulnerabilities:

File: {relative_file_path}
Code:
```
{content}
```

Assistant:"""
                        
                        request_body = {
                            "anthropic_version": "bedrock-2023-05-31",
                            "max_tokens": 4096,
                            "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
                        }
                        
                        response = bedrock_runtime.invoke_model(
                            modelId=MODEL_ID,
                            body=json.dumps(request_body)
                        )
                        
                        response_body = json.loads(response.get('body').read())
                        analysis_result = response_body.get('content', [{}])[0].get('text', '')

                        if analysis_result and "No vulnerabilities found" not in analysis_result:
                            vulnerabilities_found_overall = True
                            yield f"data: {json.dumps({'type': 'vulnerability', 'payload': {'file': relative_file_path, 'analysis': analysis_result}})}\n\n"
                            await asyncio.sleep(0.1)
                        else:
                            yield f"data: {json.dumps({'type': 'info', 'payload': f'No vulnerabilities found in: {relative_file_path}'})}\n\n"
                            await asyncio.sleep(0.1)

                    except Exception as e:
                        error_message = f"Error processing file {relative_file_path}: {str(e)}"
                        print(error_message)
                        yield f"data: {json.dumps({'type': 'error', 'payload': error_message})}\n\n"
                        await asyncio.sleep(0.1)
        
        if scanned_files_count == 0:
            yield f"data: {json.dumps({'type': 'status', 'payload': 'No supported files found to scan in the repository.'})}\n\n"
        elif not vulnerabilities_found_overall:
             yield f"data: {json.dumps({'type': 'status', 'payload': 'Scan complete. No vulnerabilities found in supported files.'})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'status', 'payload': 'Scan complete. Vulnerabilities were found.'})}\n\n"
        await asyncio.sleep(0.1)

    except Exception as e:
        error_detail = f"An unexpected error occurred during scanning: {str(e)}"
        print(error_detail)
        yield f"data: {json.dumps({'type': 'critical_error', 'payload': error_detail})}\n\n"
        await asyncio.sleep(0.1)
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            yield f"data: {json.dumps({'type': 'status', 'payload': 'Cleaned up temporary files.'})}\n\n"
            await asyncio.sleep(0.1)
        
        yield f"data: {json.dumps({'type': 'done', 'payload': 'Process finished.'})}\n\n"

@app.post("/scan_repository")
async def scan_repository_endpoint(request: RepositoryScanRequest): # Request model now includes access_token
    return StreamingResponse(stream_scan_events(request.repository_url, request.access_token), media_type="text/event-stream") # Pass token

# To run the app (from the 'backend' directory):
# uvicorn main:app --reload
