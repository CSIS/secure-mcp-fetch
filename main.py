from fastmcp import FastMCP
import requests
import socket
import ipaddress
import os
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlparse
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import re
import html2text

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

def convert_html_to_markdown(html_content: str, content_type: str = "") -> str:
    """
    Convert HTML content to clean markdown format, removing scripts, styles, and unwanted elements
    
    Args:
        html_content: Raw HTML content
        content_type: Content-Type header to determine if it's HTML
    
    Returns:
        Clean markdown content
    """
    # Only process if it's HTML content
    if not content_type or "text/html" not in content_type.lower():
        return html_content
    
    try:
        # First, clean the HTML with BeautifulSoup to remove unwanted elements
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Remove script, style, and other unwanted elements
        for element in soup(["script", "style", "meta", "link", "noscript", "head"]):
            element.decompose()
        
        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, soup.__class__.__bases__[0])):
            if hasattr(comment, 'extract'):
                comment.extract()
        
        # Get the cleaned HTML
        cleaned_html = str(soup)
        
        # Configure html2text converter
        h = html2text.HTML2Text()
        h.ignore_links = False  # Keep links as markdown links
        h.ignore_images = False  # Keep images as markdown images
        h.body_width = 0  # Don't wrap lines
        h.ignore_emphasis = False  # Keep bold/italic formatting
        h.ignore_tables = False  # Convert tables to markdown
        h.single_line_break = False  # Use proper line breaks
        h.mark_code = True  # Mark code blocks
        h.wrap_links = False  # Don't wrap link URLs
        h.unicode_snob = True  # Use unicode characters when possible
        h.escape_snob = True  # Escape special markdown characters when needed
        
        # Convert HTML to markdown
        markdown_content = h.handle(cleaned_html)
        
        # Clean up the markdown output
        # Remove excessive blank lines (more than 2 consecutive)
        markdown_content = re.sub(r'\n{3,}', '\n\n', markdown_content)
        
        # Clean up leading/trailing whitespace
        markdown_content = markdown_content.strip()
        
        return markdown_content
        
    except Exception as e:
        # If conversion fails, fall back to basic text extraction
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            for script in soup(["script", "style", "meta", "link", "noscript"]):
                script.decompose()
            text = soup.get_text()
            text = re.sub(r'\s+', ' ', text)
            lines = [line.strip() for line in text.splitlines()]
            clean_lines = [line for line in lines if line]
            return '\n'.join(clean_lines)
        except:
            return html_content

@mcp.tool()
def fetch_url(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, output_format: str = "markdown") -> Dict[str, Any]:
    """
    Fetch a URL and return response details
    
    Args:
        url: The URL to fetch
        method: HTTP method to use (default: GET)
        headers: Optional HTTP headers
        output_format: Output format - "markdown" to convert HTML to markdown, "html" to keep original HTML (default: "markdown")
    
    Returns:
        Dictionary containing status_code, content (markdown or HTML), and metadata
    """
    # Initialize headers if None
    if headers is None:
        headers = {}
    
    # Validate output_format parameter
    if output_format not in ["markdown", "html"]:
        return {
            "status_code": 400,
            "content": f"Invalid output_format '{output_format}'. Must be 'markdown' or 'html'.",
            "output_type": "error"
        }
    
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
        
        # Get response content
        response_body = response.text
        original_content_type = response.headers.get('content-type', '')
        
        # Determine output type and process content accordingly
        if output_format == "markdown" and "text/html" in original_content_type.lower():
            # Convert HTML to markdown
            processed_content = convert_html_to_markdown(response_body, original_content_type)
            output_type = "markdown"
        else:
            # Keep original content (HTML or other formats)
            processed_content = response_body
            if "text/html" in original_content_type.lower():
                output_type = "html"
            else:
                output_type = original_content_type.split(';')[0] if original_content_type else "text/plain"
        
        return {
            "status_code": response.status_code,
            "content": processed_content,
            "redirect_count": redirect_count,
            "final_url": current_url,
            "original_content_type": original_content_type,
            "output_type": output_type
        }
    except ValueError as e:
        return {
            "status_code": 403,
            "content": str(e),
            "output_type": "error"
        }
    except RequestException as e:
        return {
            "status_code": 0,
            "content": str(e),
            "output_type": "error"
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

