from fastmcp import FastMCP
import requests
import socket
import ipaddress
import os
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlparse
from requests.exceptions import RequestException

mcp = FastMCP("Secure Fetch")

# Parse allowlist from environment variable
def get_allowlist() -> List[str]:
    """Get allowlist of allowed internal domains/IPs from environment variable"""
    allowlist_env = os.environ.get("SECURE_FETCH_ALLOWLIST", "")
    if not allowlist_env:
        return []
    return [item.strip() for item in allowlist_env.split(",")]

# Initialize allowlist
ALLOWLIST = get_allowlist()

def is_private_ip(ip: str, hostname: str = None) -> bool:
    """Check if an IP address is private/internal and not in the allowlist"""
    try:
        # If the hostname or IP is in the allowlist, allow it
        if hostname and hostname in ALLOWLIST:
            return False
        if ip in ALLOWLIST:
            return False
            
        # Otherwise, check if it's a private/internal IP
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # If we can't parse it, consider it unsafe

def resolve_domain(url: str) -> Tuple[str, str, str]:
    """
    Resolve domain to IP and return the IP, original host, and scheme
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.split(':')[0]
    scheme = parsed_url.scheme
    try:
        ip = socket.gethostbyname(hostname)
        if is_private_ip(ip, hostname):
            raise ValueError(f"IP {ip} is private/internal and not allowed")
        return ip, hostname, scheme
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

@mcp.tool()
def fetch_url(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Fetch a URL and return response details
    
    Args:
        url: The URL to fetch
        method: HTTP method to use (default: GET)
        headers: Optional HTTP headers
    
    Returns:
        Dictionary containing status_code, body, and length
    """
    # Initialize headers if None
    if headers is None:
        headers = {}
    
    try:
        # Track redirects
        redirect_count = 0
        max_redirects = 3
        current_url = url
        
        while redirect_count <= max_redirects:
            # Resolve domain to IP and validate
            ip, hostname, scheme = resolve_domain(current_url)

            # Ensure scheme is either http or https
            if scheme.lower() not in ["http", "https"]:
                raise ValueError(f"Scheme '{scheme}' is not allowed. Only http and https are permitted.")
            
            
            # Rebuild URL with IP but maintain path and query
            parsed_url = urlparse(current_url)
            port = f":{parsed_url.port}" if parsed_url.port else ""
            path = parsed_url.path if parsed_url.path else ""
            query = f"?{parsed_url.query}" if parsed_url.query else ""
            ip_url = f"{scheme}://{ip}{port}{path}{query}"
            
            # Set Host header to original hostname
            request_headers = headers.copy()
            request_headers['Host'] = hostname
            
            # Create a session to set SNI parameters for HTTPS
            session = requests.Session()
            if scheme.lower() == "https":
                # Set SNI to match the hostname for HTTPS connections
                session.get_adapter('https://').poolmanager.connection_pool_kw['server_hostname'] = hostname
                session.get_adapter('https://').poolmanager.connection_pool_kw['assert_hostname'] = hostname
            
            # Make request with redirect disabled
            response = session.request(
                method=method, 
                url=ip_url, 
                headers=request_headers,
                allow_redirects=False
            )
            
            # Check if it's a redirect
            if 300 <= response.status_code < 400:
                redirect_count += 1
                if redirect_count > max_redirects:
                    break
                
                # Get the redirect URL
                redirect_url = response.headers.get('Location')
                if not redirect_url:
                    break
                
                # Handle relative redirects
                if not redirect_url.startswith(('http://', 'https://')):
                    parsed_original = urlparse(current_url)
                    base = f"{parsed_original.scheme}://{parsed_original.netloc}"
                    redirect_url = base + redirect_url if redirect_url.startswith('/') else redirect_url
                
                current_url = redirect_url
                continue
            else:
                # No redirect, return the response
                break
        
        response_body = response.text
        return {
            "status_code": response.status_code,
            "body": response_body,
            "length": len(response_body),
            "redirect_count": redirect_count,
            "final_url": current_url
        }
    except ValueError as e:
        return {
            "status_code": 403,
            "body": str(e),
            "length": 0
        }
    except RequestException as e:
        return {
            "status_code": 0,
            "body": str(e),
            "length": 0
        }

if __name__ == "__main__":
    import uvicorn
    
    # Create HTTP app with JSON responses and stateless operation
    app = mcp.http_app(
        json_response=True,
        stateless_http=True,
        transport="streamable-http"
    )
    
    # Run with uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

