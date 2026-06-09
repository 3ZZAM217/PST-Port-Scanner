import asyncio

async def run_vuln_checks(target: str, port: int, service: str, timeout: float = 2.0) -> list:
    """
    Runs a series of vulnerability checks based on the port or identified service.
    Returns a list of identified vulnerabilities (strings).
    """
    vulns = []
    
    # HTTP Checks (Port 80, 443, 8080, or banner contains HTTP)
    if port in [80, 443, 8080, 8443] or "HTTP" in service.upper():
        vulns.extend(await check_http_vulns(target, port, timeout))
        
    # FTP Checks (Port 21 or banner contains FTP)
    if port == 21 or "FTP" in service.upper():
        vulns.extend(await check_ftp_anon(target, port, timeout))
        
    # SMTP Checks (Port 25 or banner contains SMTP)
    if port == 25 or "SMTP" in service.upper():
        vulns.extend(await check_smtp_vrfy(target, port, timeout))
        
    return vulns

async def check_http_vulns(target: str, port: int, timeout: float) -> list:
    vulns = []
    try:
        conn = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Check for exposed .env
        payload = b"GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n"
        writer.write(payload)
        await writer.drain()
        
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        response = data.decode('utf-8', errors='ignore')
        
        if "HTTP/1.1 200" in response and ("DB_PASSWORD" in response or "SECRET" in response):
            vulns.append("[VULN] Exposed .env file found!")
            
        # Check HTTP methods (OPTIONS)
        conn2 = asyncio.open_connection(target, port)
        reader2, writer2 = await asyncio.wait_for(conn2, timeout=timeout)
        payload2 = b"OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        writer2.write(payload2)
        await writer2.drain()
        
        data2 = await asyncio.wait_for(reader2.read(2048), timeout=timeout)
        response2 = data2.decode('utf-8', errors='ignore')
        
        if "Allow:" in response2:
            allowed = response2.split("Allow:")[1].split("\r\n")[0].strip()
            vulns.append(f"[INFO] Allowed HTTP Methods: {allowed}")
            if "PUT" in allowed or "DELETE" in allowed:
                vulns.append("[VULN] Dangerous HTTP methods enabled (PUT/DELETE)")
                
        writer.close()
        writer2.close()

    except Exception:
        pass
    return vulns

async def check_ftp_anon(target: str, port: int, timeout: float) -> list:
    vulns = []
    try:
        conn = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Read initial banner
        await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        # Send anonymous login
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        response = data.decode('utf-8', errors='ignore')
        
        if "331" in response: # Password required for anonymous
            writer.write(b"PASS anonymous@example.com\r\n")
            await writer.drain()
            data2 = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            response2 = data2.decode('utf-8', errors='ignore')
            
            if "230" in response2:
                vulns.append("[VULN] Anonymous FTP Login Allowed!")
        
        writer.close()
    except Exception:
        pass
    return vulns

async def check_smtp_vrfy(target: str, port: int, timeout: float) -> list:
    vulns = []
    try:
        conn = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Read banner
        await asyncio.wait_for(reader.read(1024), timeout=timeout)
        
        # Send VRFY
        writer.write(b"VRFY root\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        response = data.decode('utf-8', errors='ignore')
        
        if "250" in response or "252" in response:
            vulns.append("[VULN] SMTP VRFY Command Allowed (User Enumeration possible)")
            
        writer.close()
    except Exception:
        pass
    return vulns
