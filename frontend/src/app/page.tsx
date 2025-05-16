'use client';

import React, { useState, FormEvent, useEffect, useRef } from 'react';

type MessageType = 'status' | 'info' | 'error' | 'critical_error' | 'vulnerability' | 'done';

interface ProgressMessage {
  id: number;
  type: MessageType;
  payload: string | VulnerabilityPayload;
}

interface VulnerabilityPayload {
  file: string;
  analysis: string;
}

interface ErrorResponse {
  detail: string;
}

interface ScanRequest {
  repository_url: string;
  access_token?: string;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function HomePage() {
  const [repoUrl, setRepoUrl] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [progressMessages, setProgressMessages] = useState<ProgressMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isStreamFinished, setIsStreamFinished] = useState(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    setProgressMessages([]);
    setIsStreamFinished(false);
    let messageIdCounter = 0;

    abortControllerRef.current = new AbortController();

    try {
      const requestBody: ScanRequest = {
        repository_url: repoUrl,
        access_token: accessToken || undefined,
      };

      const response = await fetch(`${API_URL}/scan_repository`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
        signal: abortControllerRef.current.signal,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ 
          detail: `HTTP error! status: ${response.status}` 
        })) as ErrorResponse;
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      if (!response.body) {
        throw new Error('Response body is null.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      const processStream = async () => {
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            setIsStreamFinished(true);
            break;
          }

          const chunk = decoder.decode(value, { stream: true });
          const sseMessages = chunk.split('\n\n').filter(msg => msg.trim() !== '');

          sseMessages.forEach(sseMessage => {
            if (sseMessage.startsWith('data:')) {
              try {
                const jsonData = sseMessage.substring(5).trim();
                const parsedEvent = JSON.parse(jsonData) as ProgressMessage;
                
                setProgressMessages(prev => [...prev, { 
                  id: messageIdCounter++, 
                  type: parsedEvent.type,
                  payload: parsedEvent.payload
                }]);

                if (parsedEvent.type === 'done') {
                  setIsStreamFinished(true);
                }
                if (parsedEvent.type === 'critical_error') {
                  setError(`Backend Error: ${parsedEvent.payload}`);
                  setIsStreamFinished(true);
                }
              } catch (e) {
                console.error('Failed to parse SSE message:', sseMessage, e);
              }
            }
          });
        }
      };

      await processStream();

    } catch (err) {
      if (err instanceof Error) {
        if (err.name === 'AbortError') {
          setError('Scan was stopped by user');
        } else {
          setError(err.message || 'Failed to start scan. Please check the URL and backend server.');
        }
      } else {
        setError('An unexpected error occurred');
      }
      console.error("Scan error:", err);
      setIsStreamFinished(true);
    }
  };

  const handleStop = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setIsLoading(false);
      setIsStreamFinished(true);
    }
  };

  useEffect(() => {
    if (isStreamFinished || error) {
      setIsLoading(false);
    }
  }, [isStreamFinished, error]);

  const renderPayload = (message: ProgressMessage) => {
    if (message.type === 'vulnerability') {
      const vuln = message.payload as VulnerabilityPayload;
      return (
        <div className="bg-gray-800 p-4 rounded-md shadow-sm border border-gray-700">
          <h4 className="text-md font-semibold text-yellow-400 mb-1">File: {vuln.file}</h4>
          <pre className="bg-gray-900 p-2 rounded-sm overflow-x-auto text-xs whitespace-pre-wrap">{vuln.analysis}</pre>
        </div>
      );
    }
    if (typeof message.payload === 'string') {
      return <span>{message.payload}</span>;
    }
    return <span>{JSON.stringify(message.payload)}</span>;
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-start p-8 bg-[#000000] text-white">
      <div className="w-full max-w-3xl">
        <h1 className="text-4xl font-bold mb-8 text-center text-white">AWS Bedrock Security Checker</h1>

        <form onSubmit={handleSubmit} className="mb-8 space-y-6">
          <div className="space-y-4">
            <label htmlFor="repoUrl" className="block text-sm font-medium text-gray-300">
              GitHub or Bitbucket Repository URL
            </label>
            <input
              type="url"
              id="repoUrl"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              className="w-full p-4 border border-gray-700 rounded-xl shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-[#1c1c1e] text-white placeholder-gray-500 transition-all duration-200"
              placeholder="https://github.com/user/repo.git"
              required
              disabled={isLoading}
            />
          </div>
          
          <div className="space-y-4">
            <label htmlFor="accessToken" className="block text-sm font-medium text-gray-300">
              Personal Access Token (Optional)
            </label>
            <input
              type="password"
              id="accessToken"
              value={accessToken}
              onChange={(e) => setAccessToken(e.target.value)}
              className="w-full p-4 border border-gray-700 rounded-xl shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-[#1c1c1e] text-white placeholder-gray-500 transition-all duration-200"
              placeholder="Enter your PAT if accessing a private repository"
              disabled={isLoading}
            />
            <p className="text-xs text-gray-400">
              Your PAT is sent to the backend to clone the repository and is not stored long-term.
            </p>
          </div>

          <div className="flex gap-4">
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 bg-[#007AFF] hover:bg-[#0066CC] text-white font-semibold py-4 px-6 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:bg-gray-500 transition-all duration-200"
            >
              {isLoading ? 'Scanning...' : 'Start Scan'}
            </button>
            
            {isLoading && (
              <button
                type="button"
                onClick={handleStop}
                className="flex-1 bg-[#FF3B30] hover:bg-[#CC2E26] text-white font-semibold py-4 px-6 rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition-all duration-200"
              >
                Stop Scan
              </button>
            )}
          </div>
        </form>

        {error && (
          <div className="bg-[#FF3B30] bg-opacity-10 border border-[#FF3B30] text-white px-6 py-4 rounded-xl mb-6" role="alert">
            <strong className="font-semibold">Error: </strong>
            <span className="block sm:inline">{error}</span>
          </div>
        )}

        {(isLoading || progressMessages.length > 0) && (
          <div className="mt-8">
            <h2 className="text-2xl font-semibold mb-4 text-white">Scan Progress & Results</h2>
            <div className="space-y-3 bg-[#1c1c1e] p-6 rounded-xl max-h-96 overflow-y-auto border border-gray-700">
              {progressMessages.map((msg) => (
                <div key={msg.id} className={`p-4 rounded-xl text-sm ${
                  msg.type === 'error' || msg.type === 'critical_error' ? 'bg-[#FF3B30] bg-opacity-10 border border-[#FF3B30]' :
                  msg.type === 'vulnerability' ? 'bg-[#FF9500] bg-opacity-10 border border-[#FF9500]' :
                  msg.type === 'status' ? 'bg-[#007AFF] bg-opacity-10 border border-[#007AFF]' :
                  'bg-[#2c2c2e] border border-gray-700'
                }`}
                >
                  <strong className="capitalize">[{msg.type.replace('_', ' ')}]: </strong>
                  {renderPayload(msg)}
                </div>
              ))}
              {isLoading && !isStreamFinished && (
                <div className="p-4 rounded-xl text-sm bg-[#2c2c2e] text-gray-200 animate-pulse">
                  Waiting for more updates...
                </div>
              )}
              {isStreamFinished && progressMessages.length > 0 && (
                <div className="p-4 mt-2 rounded-xl text-sm bg-[#34C759] bg-opacity-10 border border-[#34C759] text-[#34C759] font-semibold">
                  Scan process finished
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
