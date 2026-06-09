import asyncio

# Common payloads to elicit responses from silent services
PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",  # HTTP
    b"\r\n\r\n",                                  # Generic trigger
    b"HELP\r\n",                                  # FTP/SMTP/POP3
]

async def fingerprint_service(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float = 1.0) -> str:
    """
    Attempts to fingerprint the service by passively listening,
    and then actively probing if no response is received.
    """
    try:
        # 1. Passive banner grabbing
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if data:
                return parse_banner(data)
        except asyncio.TimeoutError:
            pass # No passive banner, proceed to active

        # 2. Active probing
        for payload in PAYLOADS:
            try:
                writer.write(payload)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                if data:
                    return parse_banner(data)
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                continue
            
    except Exception:
        pass
        
    return "Unknown"

def parse_banner(data: bytes) -> str:
    banner = data.decode('utf-8', errors='ignore').strip()
    # Clean up multi-line banners for display
    banner = ' '.join(banner.splitlines())
    if not banner:
        return "Unknown"
    
    # Simple heuristic identifying
    upper_banner = banner.upper()
    if "HTTP" in upper_banner or "HTML" in upper_banner:
        return f"HTTP Service ({banner[:50]}...)"
    elif "SSH-" in upper_banner:
        return f"SSH ({banner[:50]})"
    elif "FTP" in upper_banner:
        return f"FTP ({banner[:50]})"
    elif "SMTP" in upper_banner:
        return f"SMTP ({banner[:50]})"
    
    return banner[:100]  # Return up to 100 chars
