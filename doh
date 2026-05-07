let DoH = "cloudflare-dns.com";
const jsonDoH = `https://${DoH}/resolve`;
const dnsDoH = `https://${DoH}/dns-query`;
let DoH路径 = 'dns-query';

export default {
  async fetch(request, env) {
    if (env.DOH) {
      DoH = env.DOH;
      const match = DoH.match(/:\/\/([^\/]+)/);
      if (match) {
        DoH = match[1];
      }
    }
    // TOKEN 不允许包含 /，取第一段作为路径
    const rawPath = env.PATH || env.TOKEN || DoH路径;
    DoH路径 = rawPath.includes("/") ? rawPath.split("/")[0] : rawPath;

    const url = new URL(request.url);
    const path = url.pathname;

    // 处理 OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // DoH 服务端点
    if (path === `/${DoH路径}`) {
      return await DOHRequest(request);
    }

    // IP 地理位置查询代理
    if (path === '/ip-info') {
      // 仅在设置了 TOKEN 时要求鉴权，否则完全公开
      if (env.TOKEN) {
        const token = url.searchParams.get('token');
        if (token !== env.TOKEN) {
          return new Response(JSON.stringify({
            status: "error",
            message: "Token 不正确",
            code: "AUTH_FAILED",
            timestamp: new Date().toISOString()
          }, null, 4), {
            status: 403,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              'Access-Control-Allow-Origin': '*'
            }
          });
        }
      }

      const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(JSON.stringify({
          status: "error",
          message: "IP 参数未提供",
          code: "MISSING_PARAMETER",
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`, {
          signal: controller.signal
        });
        clearTimeout(timer);

        if (!response.ok) throw new Error(`HTTP error: ${response.status}`);

        const data = await response.json();
        data.timestamp = new Date().toISOString();

        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });

      } catch (error) {
        console.error("IP 查询失败:", error);
        return new Response(JSON.stringify({
          status: "error",
          message: `IP 查询失败: ${error.message}`,
          code: error.name === 'AbortError' ? 'TIMEOUT' : "API_REQUEST_FAILED",
          query: ip,
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // DNS 解析代理
    if (url.searchParams.has("doh")) {
      const domain = url.searchParams.get("domain") || url.searchParams.get("name") || "www.google.com";
      const doh = url.searchParams.get("doh") || dnsDoH;
      const type = url.searchParams.get("type") || "all";

      // 如果指向当前站点，直接用上游 DoH
      if (doh.includes(url.host)) {
        return await handleDnsQuery(domain, type, true);
      }

      try {
        return await handleDnsQuery(domain, type, false, doh);
      } catch (err) {
        console.error("DNS 查询失败:", err);
        return new Response(JSON.stringify({
          error: `DNS 查询失败: ${err.message}`,
          doh, domain
        }, null, 2), {
          headers: { "content-type": "application/json; charset=UTF-8" },
          status: 500
        });
      }
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    else if (env.URL) {
      if (env.URL.toString().toLowerCase() === 'nginx') {
        return new Response(await nginx(), {
          headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
      } else return await proxyURL(env.URL, url);
    } else return await HTML();
  }
}

// ─── DNS 查询超时封装 ────────────────────────────────────────────────────────

function withTimeout(promise, ms = 5000) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`请求超时 (${ms}ms)`)), ms)
    )
  ]);
}

// ─── 通用 DNS 查询函数 ────────────────────────────────────────────────────────

async function queryDns(dohServer, domain, type) {
  const dohUrl = new URL(dohServer);
  dohUrl.searchParams.set("name", domain);
  dohUrl.searchParams.set("type", type);

  // 按优先级尝试两种 Accept 头
  const acceptHeaders = [
    'application/dns-json',
    'application/json'
  ];

  let lastError = null;

  for (const accept of acceptHeaders) {
    try {
      const response = await withTimeout(
        fetch(dohUrl.toString(), { headers: { 'Accept': accept } })
      );

      if (!response.ok) {
        const errText = await response.text();
        lastError = new Error(`DoH 返回错误 (${response.status}): ${errText.substring(0, 200)}`);
        continue;
      }

      const ct = response.headers.get('content-type') || '';
      if (ct.includes('json') || ct.includes('dns-json')) {
        return await response.json();
      }

      // 非标准 Content-Type，仍尝试解析
      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch (e) {
        lastError = new Error(`无法解析响应为 JSON: ${e.message}`);
        continue;
      }
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError || new Error("DNS 查询失败");
}

// ─── 统一的 DNS 查询处理（合并了原来两处重复逻辑）───────────────────────────

async function handleDnsQuery(domain, type, useLocalUpstream, dohServer) {
  const upstream = useLocalUpstream
    ? `https://${DoH}/dns-query`
    : dohServer;

  try {
    if (type === "all") {
      const [ipv4Result, ipv6Result, nsResult] = await Promise.all([
        withTimeout(queryDns(upstream, domain, "A")),
        withTimeout(queryDns(upstream, domain, "AAAA")),
        withTimeout(queryDns(upstream, domain, "NS"))
      ]);

      const nsRecords = [];

      if (nsResult.Answer?.length) {
        nsRecords.push(...nsResult.Answer.filter(r => r.type === 2));
      }
      if (nsResult.Authority?.length) {
        nsRecords.push(...nsResult.Authority.filter(r => r.type === 2 || r.type === 6));
      }

      // 合并 Question 字段（兼容对象和数组两种格式）
      const mergeQuestion = (q) => {
        if (!q) return [];
        return Array.isArray(q) ? q : [q];
      };

      const combinedResult = {
        Status: ipv4Result.Status ?? ipv6Result.Status ?? nsResult.Status,
        TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
        RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
        RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
        AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
        CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
        Question: [
          ...mergeQuestion(ipv4Result.Question),
          ...mergeQuestion(ipv6Result.Question),
          ...mergeQuestion(nsResult.Question)
        ],
        Answer: [
          ...(ipv4Result.Answer || []),
          ...(ipv6Result.Answer || []),
          ...nsRecords
        ],
        ipv4: { records: ipv4Result.Answer || [] },
        ipv6: { records: ipv6Result.Answer || [] },
        ns: { records: nsRecords }
      };

      return new Response(JSON.stringify(combinedResult, null, 2), {
        headers: {
          "content-type": "application/json; charset=UTF-8",
          'Access-Control-Allow-Origin': '*'
        }
      });
    } else {
      const result = await withTimeout(queryDns(upstream, domain, type));
      return new Response(JSON.stringify(result, null, 2), {
        headers: {
          "content-type": "application/json; charset=UTF-8",
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  } catch (err) {
    console.error("DoH 查询失败:", err);
    return new Response(JSON.stringify({
      error: `DoH 查询失败: ${err.message}`
    }, null, 2), {
      headers: {
        "content-type": "application/json; charset=UTF-8",
        'Access-Control-Allow-Origin': '*'
      },
      status: 500
    });
  }
}

// ─── DoH 请求转发处理 ────────────────────────────────────────────────────────

async function DOHRequest(request) {
  const { method, headers, body } = request;
  const UA = headers.get('User-Agent') || 'DoH Client';
  const url = new URL(request.url);
  const { searchParams } = url;
  const currentDnsDoH = `https://${DoH}/dns-query`;
  const currentJsonDoH = `https://${DoH}/resolve`;

  try {
    if (method === 'GET' && !url.search) {
      return new Response('Bad Request', {
        status: 400,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    let response;

    if (method === 'GET' && searchParams.has('name')) {
      const searchDoH = searchParams.has('type') ? url.search : url.search + '&type=A';
      response = await withTimeout(fetch(currentDnsDoH + searchDoH, {
        headers: { 'Accept': 'application/dns-json', 'User-Agent': UA }
      }));
      if (!response.ok) {
        response = await withTimeout(fetch(currentJsonDoH + searchDoH, {
          headers: { 'Accept': 'application/dns-json', 'User-Agent': UA }
        }));
      }
    } else if (method === 'GET') {
      response = await withTimeout(fetch(currentDnsDoH + url.search, {
        headers: { 'Accept': 'application/dns-message', 'User-Agent': UA }
      }));
    } else if (method === 'POST') {
      response = await withTimeout(fetch(currentDnsDoH, {
        method: 'POST',
        headers: {
          'Accept': 'application/dns-message',
          'Content-Type': 'application/dns-message',
          'User-Agent': UA
        },
        body
      }));
    } else {
      return new Response('不支持的请求格式', {
        status: 400,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`DoH 返回错误 (${response.status}): ${errorText.substring(0, 200)}`);
    }

    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', '*');

    if (method === 'GET' && searchParams.has('name')) {
      responseHeaders.set('Content-Type', 'application/json');
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });

  } catch (error) {
    console.error("DoH 请求处理错误:", error);
    return new Response(JSON.stringify({
      error: `DoH 请求处理错误: ${error.message}`
    }, null, 4), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// ─── HTML 前端页面 ────────────────────────────────────────────────────────────

async function HTML() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS-over-HTTPS Resolver</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="icon"
    href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg"
    type="image/x-icon">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      min-height: 100vh;
      padding: 0;
      margin: 0;
      line-height: 1.6;
      background: url('https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5B5shLB8bSKIyB9NJ6R1jz/87e7617be2c61603d46003cb3f1bd382/Hero-globe-bg-takeover-xxl.png'),
        linear-gradient(135deg, rgba(253, 101, 60, 0.85) 0%, rgba(251,152,30, 0.85) 100%);
      background-size: cover;
      background-position: center center;
      background-repeat: no-repeat;
      background-attachment: fixed;
      padding: 30px 20px;
      box-sizing: border-box;
    }
    .page-wrapper { width: 100%; max-width: 800px; margin: 0 auto; }
    .container {
      width: 100%; max-width: 800px; margin: 20px auto;
      background-color: rgba(255, 255, 255, 0.65);
      border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.15);
      padding: 30px; backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.4);
    }
    h1 {
      background-image: linear-gradient(to right, rgb(249,171,76), rgb(252,103,60));
      color: rgb(252, 103, 60);
      -webkit-background-clip: text; background-clip: text;
      -webkit-text-fill-color: transparent;
      font-weight: 600; text-shadow: none;
    }
    .card {
      margin-bottom: 20px; border: none;
      box-shadow: 0 2px 10px rgba(0,0,0,0.05);
      background-color: rgba(255, 255, 255, 0.8);
      backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px);
    }
    .card-header {
      background-color: rgba(255, 242, 235, 0.9);
      font-weight: 600; padding: 12px 20px; border-bottom: none;
    }
    .form-label { font-weight: 500; margin-bottom: 8px; color: rgb(70, 50, 40); }
    .form-select, .form-control {
      border-radius: 6px; padding: 10px;
      border: 1px solid rgba(253, 101, 60, 0.3);
      background-color: rgba(255, 255, 255, 0.9);
    }
    .btn-primary {
      background-color: rgb(253, 101, 60); border: none;
      border-radius: 6px; padding: 10px 20px;
      font-weight: 500; transition: all 0.2s ease;
    }
    .btn-primary:hover { background-color: rgb(230, 90, 50); transform: translateY(-1px); }
    pre {
      background-color: rgba(255, 245, 240, 0.9); padding: 15px;
      border-radius: 6px; border: 1px solid rgba(253, 101, 60, 0.2);
      white-space: pre-wrap; word-break: break-all;
      font-family: Consolas, Monaco, 'Andale Mono', monospace;
      font-size: 14px; max-height: 400px; overflow: auto;
    }
    .loading { display: none; text-align: center; padding: 20px 0; }
    .loading-spinner {
      border: 4px solid rgba(0,0,0,0.1);
      border-left: 4px solid rgb(253, 101, 60);
      border-radius: 50%; width: 30px; height: 30px;
      animation: spin 1s linear infinite; margin: 0 auto 10px;
    }
    .badge { margin-left: 5px; font-size: 11px; vertical-align: middle; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .footer { margin-top: 30px; text-align: center; color: rgba(255,255,255,0.9); font-size: 14px; }
    .beian-info { text-align: center; font-size: 13px; }
    .beian-info a { color: var(--primary-color); text-decoration: none; border-bottom: 1px dashed var(--primary-color); padding-bottom: 2px; }
    .beian-info a:hover { border-bottom-style: solid; }
    .error-message { color: #e63e00; margin-top: 10px; }
    .success-message { color: #e67e22; }
    .nav-tabs .nav-link {
      border-top-left-radius: 6px; border-top-right-radius: 6px;
      padding: 8px 16px; font-weight: 500; color: rgb(150, 80, 50);
    }
    .nav-tabs .nav-link.active {
      background-color: rgba(255, 245, 240, 0.8);
      border-bottom-color: rgba(255, 245, 240, 0.8);
      color: rgb(253, 101, 60);
    }
    .tab-content {
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 0 0 6px 6px; padding: 15px;
      border: 1px solid rgba(253, 101, 60, 0.2); border-top: none;
    }
    .ip-record {
      padding: 5px 10px; margin-bottom: 5px; border-radius: 4px;
      background-color: rgba(255, 255, 255, 0.9);
      border: 1px solid rgba(253, 101, 60, 0.15);
    }
    .ip-record:hover { background-color: rgba(255, 235, 225, 0.9); }
    .ip-address {
      font-family: monospace; font-weight: 600;
      min-width: 130px; color: rgb(80, 60, 50);
      cursor: pointer; position: relative;
      transition: color 0.2s ease; display: inline-block;
    }
    .ip-address:hover { color: rgb(253, 101, 60); }
    .ip-address:after {
      content: ''; position: absolute;
      left: 100%; top: 0; opacity: 0;
      white-space: nowrap; font-size: 12px;
      color: rgb(253, 101, 60); transition: opacity 0.3s ease;
      font-family: 'Segoe UI', sans-serif; font-weight: normal;
    }
    .ip-address.copied:after { content: '✓ 已复制'; opacity: 1; }
    .result-summary {
      margin-bottom: 15px; padding: 10px;
      background-color: rgba(255, 235, 225, 0.8); border-radius: 6px;
    }
    .result-tabs { margin-bottom: 20px; }
    .geo-info { margin: 0 10px; font-size: 0.85em; flex-grow: 1; text-align: center; }
    .geo-country {
      color: rgb(230, 90, 50); font-weight: 500; padding: 2px 6px;
      background-color: rgba(255, 245, 240, 0.8); border-radius: 4px; display: inline-block;
    }
    .geo-as {
      color: rgb(253, 101, 60); padding: 2px 6px;
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 4px; margin-left: 5px; display: inline-block;
    }
    .geo-blocked {
      color: #ffffff; background-color: #dc3545;
      padding: 2px 8px; border-radius: 4px; font-weight: 600;
      display: inline-block; animation: pulse-red 2s infinite;
    }
    @keyframes pulse-red {
      0% { box-shadow: 0 0 0 0 rgba(220,53,69,0.7); }
      70% { box-shadow: 0 0 0 10px rgba(220,53,69,0); }
      100% { box-shadow: 0 0 0 0 rgba(220,53,69,0); }
    }
    .geo-loading { color: rgb(150, 100, 80); font-style: italic; }
    .ttl-info { min-width: 80px; text-align: right; color: rgb(180, 90, 60); }
    .copy-link {
      color: rgb(253, 101, 60); text-decoration: none;
      border-bottom: 1px dashed rgb(253, 101, 60);
      padding-bottom: 2px; cursor: pointer; position: relative;
    }
    .copy-link:hover { border-bottom-style: solid; }
    .copy-link:after {
      content: ''; position: absolute;
      top: 0; right: -65px; opacity: 0;
      white-space: nowrap; color: rgb(253, 101, 60);
      font-size: 12px; transition: opacity 0.3s ease;
    }
    .copy-link.copied:after { content: '✓ 已复制'; opacity: 1; }
    .github-corner svg {
      fill: rgb(255, 255, 255); color: rgb(251,152,30);
      position: absolute; top: 0; right: 0;
      border: 0; width: 80px; height: 80px;
    }
    .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
    @keyframes octocat-wave {
      0%, 100% { transform: rotate(0); }
      20%, 60% { transform: rotate(-25deg); }
      40%, 80% { transform: rotate(10deg); }
    }
    @media (max-width: 576px) {
      .container { padding: 20px; }
      .github-corner:hover .octo-arm { animation: none; }
      .github-corner .octo-arm { animation: octocat-wave 560ms ease-in-out; }
    }
  </style>
</head>
<body>
  <a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
        fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
        fill="currentColor" class="octo-body"></path>
    </svg>
  </a>

  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">DNS 查询设置</div>
      <div class="card-body">
        <form id="resolveForm">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">选择 DoH 地址:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected id="currentDohOption">自动 (当前站点)</option>
              <option value="https://dns.alidns.com/resolve">https://dns.alidns.com/resolve (阿里)</option>
              <option value="https://sm2.doh.pub/dns-query">https://sm2.doh.pub/dns-query (腾讯)</option>
              <option value="https://doh.360.cn/resolve">https://doh.360.cn/resolve (360)</option>
              <option value="https://cloudflare-dns.com/dns-query">https://cloudflare-dns.com/dns-query (Cloudflare)</option>
              <option value="https://dns.google/resolve">https://dns.google/resolve (谷歌)</option>
              <option value="https://dns.adguard-dns.com/resolve">https://dns.adguard-dns.com/resolve (AdGuard)</option>
              <option value="https://dns.sb/dns-query">https://dns.sb/dns-query (DNS.SB)</option>
              <option value="https://zero.dns0.eu/">https://zero.dns0.eu (dns0.eu)</option>
              <option value="https://dns.nextdns.io">https://dns.nextdns.io (NextDNS)</option>
              <option value="https://dns.rabbitdns.org/dns-query">https://dns.rabbitdns.org/dns-query (Rabbit DNS)</option>
              <option value="https://basic.rethinkdns.com/">https://basic.rethinkdns.com (RethinkDNS)</option>
              <option value="https://v.recipes/dns-query">https://v.recipes/dns-query (v.recipes DNS)</option>
              <option value="custom">自定义...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">输入自定义 DoH 地址:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/dns-query">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">待解析域名:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" value="www.google.com"
                placeholder="输入域名，如 example.com">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
            </div>
          </div>
          <div class="d-flex gap-2">
            <button type="submit" class="btn btn-primary flex-grow-1">解析</button>
            <button type="button" class="btn btn-outline-primary" id="getJsonBtn">Get Json</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>解析结果</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display:none;">复制结果</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>正在查询中，请稍候...</p>
        </div>
        <div id="resultContainer" style="display:none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button" role="tab">IPv4 地址</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button" role="tab">IPv6 地址</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS 记录</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button" role="tab">原始数据</button>
            </li>
          </ul>
          <div class="tab-content" id="resultTabContent">
            <div class="tab-pane fade show active" id="ipv4" role="tabpanel">
              <div class="result-summary" id="ipv4Summary"></div>
              <div id="ipv4Records"></div>
            </div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel">
              <div class="result-summary" id="ipv6Summary"></div>
              <div id="ipv6Records"></div>
            </div>
            <div class="tab-pane fade" id="ns" role="tabpanel">
              <div class="result-summary" id="nsSummary"></div>
              <div id="nsRecords"></div>
            </div>
            <div class="tab-pane fade" id="raw" role="tabpanel">
              <pre id="result">等待查询...</pre>
            </div>
          </div>
        </div>
        <div id="errorContainer" style="display:none;">
          <pre id="errorMessage" class="error-message"></pre>
        </div>
      </div>
    </div>

    <div class="beian-info">
      <p>
        <strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">
          https://<span id="currentDomain">...</span>/${DoH路径}
        </span></strong><br>
        基于 Cloudflare Workers 上游 ${DoH} 的 DoH (DNS over HTTPS) 解析服务
      </p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // ── 全局常量 ──────────────────────────────────────────────────────────────
    const currentHost     = window.location.host;
    const currentProtocol = window.location.protocol;
    const currentDohPath  = '${DoH路径}';
    const currentDohUrl   = currentProtocol + '//' + currentHost + '/' + currentDohPath;
    const ipInfoToken     = '${DoH路径}'; // 与路径一致，仅在服务端设置了 TOKEN 时有效

    // 阻断 IP 列表（已知的 DNS 污染/阻断地址）
    const BLOCKED_IPS = new Set([
      '104.21.16.1','104.21.32.1','104.21.48.1','104.21.64.1',
      '104.21.80.1','104.21.96.1','104.21.112.1',
      '2606:4700:3030::6815:1001','2606:4700:3030::6815:3001',
      '2606:4700:3030::6815:7001','2606:4700:3030::6815:5001'
    ]);

    // ── 安全工具 ──────────────────────────────────────────────────────────────
    // 防止 XSS：所有来自 DNS 响应的数据必须经此函数转义后再插入 DOM
    function esc(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // ── 格式化 TTL ────────────────────────────────────────────────────────────
    function formatTTL(seconds) {
      seconds = parseInt(seconds) || 0;
      if (seconds < 60)    return seconds + ' 秒';
      if (seconds < 3600)  return Math.floor(seconds / 60) + ' 分钟';
      if (seconds < 86400) return Math.floor(seconds / 3600) + ' 小时';
      return Math.floor(seconds / 86400) + ' 天';
    }

    // ── IP 地理位置查询 ───────────────────────────────────────────────────────
    async function queryIpGeoInfo(ip) {
      try {
        const resp = await fetch('./ip-info?ip=' + encodeURIComponent(ip) + '&token=' + encodeURIComponent(ipInfoToken));
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        return await resp.json();
      } catch (e) {
        console.error('IP 地理位置查询失败:', e);
        return null;
      }
    }

    // ── 点击复制 ──────────────────────────────────────────────────────────────
    function handleCopyClick(element, text) {
      navigator.clipboard.writeText(text).then(() => {
        element.classList.add('copied');
        setTimeout(() => element.classList.remove('copied'), 2000);
      }).catch(e => console.error('复制失败:', e));
    }

    // ── 构建单条 IP 记录行（使用安全的 DOM 操作，彻底防止 XSS）─────────────
    function buildIpRecordRow(data, type, ttl) {
      const row = document.createElement('div');
      row.className = 'ip-record';

      const inner = document.createElement('div');
      inner.className = 'd-flex justify-content-between align-items-center';

      // IP / 域名文字
      const ipSpan = document.createElement('span');
      ipSpan.className = 'ip-address';
      ipSpan.dataset.copy = data;
      ipSpan.textContent = data; // textContent 天然安全，无需 esc()
      ipSpan.addEventListener('click', function () { handleCopyClick(this, this.dataset.copy); });

      // 地理位置占位
      const geoSpan = document.createElement('span');
      geoSpan.className = 'geo-info geo-loading';
      geoSpan.textContent = '正在获取位置信息...';

      // TTL
      const ttlSpan = document.createElement('span');
      ttlSpan.className = 'text-muted ttl-info';
      ttlSpan.textContent = 'TTL: ' + formatTTL(ttl);

      inner.append(ipSpan, geoSpan, ttlSpan);
      row.appendChild(inner);

      // 异步填充地理位置
      queryIpGeoInfo(data).then(geoData => {
        geoSpan.innerHTML = '';
        geoSpan.classList.remove('geo-loading');

        const isBlocked = BLOCKED_IPS.has(data);

        if (isBlocked) {
          const bSpan = document.createElement('span');
          bSpan.className = 'geo-blocked';
          bSpan.textContent = '阻断 IP';
          geoSpan.appendChild(bSpan);
        } else if (geoData?.status === 'success') {
          const cSpan = document.createElement('span');
          cSpan.className = 'geo-country';
          cSpan.textContent = geoData.country || '未知国家';

          const aSpan = document.createElement('span');
          aSpan.className = 'geo-as';
          aSpan.textContent = geoData.as || '未知 AS';

          geoSpan.append(cSpan, aSpan);
        } else {
          geoSpan.textContent = '位置信息获取失败';
        }

        // 阻断 IP 也追加 AS 信息
        if (isBlocked && geoData?.status === 'success' && geoData.as) {
          const aSpan = document.createElement('span');
          aSpan.className = 'geo-as';
          aSpan.textContent = geoData.as;
          geoSpan.appendChild(aSpan);
        }
      });

      return row;
    }

    // ── 构建 CNAME 记录行 ─────────────────────────────────────────────────────
    function buildCnameRow(data, ttl) {
      const row = document.createElement('div');
      row.className = 'ip-record';

      const inner = document.createElement('div');
      inner.className = 'd-flex justify-content-between align-items-center';

      const nameSpan = document.createElement('span');
      nameSpan.className = 'ip-address';
      nameSpan.dataset.copy = data;
      nameSpan.textContent = data;
      nameSpan.addEventListener('click', function () { handleCopyClick(this, this.dataset.copy); });

      const badge = document.createElement('span');
      badge.className = 'badge bg-success';
      badge.textContent = 'CNAME';

      const ttlSpan = document.createElement('span');
      ttlSpan.className = 'text-muted ttl-info';
      ttlSpan.textContent = 'TTL: ' + formatTTL(ttl);

      inner.append(nameSpan, badge, ttlSpan);
      row.appendChild(inner);
      return row;
    }

    // ── 构建 NS 记录行 ────────────────────────────────────────────────────────
    function buildNsRow(data, ttl) {
      const row = document.createElement('div');
      row.className = 'ip-record';

      const inner = document.createElement('div');
      inner.className = 'd-flex justify-content-between align-items-center';

      const nameSpan = document.createElement('span');
      nameSpan.className = 'ip-address';
      nameSpan.dataset.copy = data;
      nameSpan.textContent = data;
      nameSpan.addEventListener('click', function () { handleCopyClick(this, this.dataset.copy); });

      const badge = document.createElement('span');
      badge.className = 'badge bg-info';
      badge.textContent = 'NS';

      const ttlSpan = document.createElement('span');
      ttlSpan.className = 'text-muted ttl-info';
      ttlSpan.textContent = 'TTL: ' + formatTTL(ttl);

      inner.append(nameSpan, badge, ttlSpan);
      row.appendChild(inner);
      return row;
    }

    // ── 构建 SOA 记录行 ───────────────────────────────────────────────────────
    function buildSoaRow(record) {
      const row = document.createElement('div');
      row.className = 'ip-record';

      const parts = String(record.data).split(' ');
      const primaryNs = parts[0] || '';

      // 修正 SOA 管理员邮箱：仅把第一个 . 替换为 @
      const mbox = parts[1] || '';
      const dotIdx = mbox.indexOf('.');
      let adminEmail = dotIdx >= 0
        ? mbox.substring(0, dotIdx) + '@' + mbox.substring(dotIdx + 1)
        : mbox;
      if (adminEmail.endsWith('.')) adminEmail = adminEmail.slice(0, -1);

      // 标题行
      const header = document.createElement('div');
      header.className = 'd-flex justify-content-between align-items-center mb-2';

      const nameSpan = document.createElement('span');
      nameSpan.className = 'ip-address';
      nameSpan.dataset.copy = record.name || '';
      nameSpan.textContent = record.name || '';
      nameSpan.addEventListener('click', function () { handleCopyClick(this, this.dataset.copy); });

      const badge = document.createElement('span');
      badge.className = 'badge bg-warning';
      badge.textContent = 'SOA';

      const ttlSpan = document.createElement('span');
      ttlSpan.className = 'text-muted ttl-info';
      ttlSpan.textContent = 'TTL: ' + formatTTL(record.TTL);

      header.append(nameSpan, badge, ttlSpan);

      // 详细信息
      const detail = document.createElement('div');
      detail.className = 'ps-3 small';

      const makeLine = (label, value, copyable) => {
        const line = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = label + '：';
        line.appendChild(strong);
        if (copyable) {
          const span = document.createElement('span');
          span.className = 'ip-address';
          span.dataset.copy = value;
          span.textContent = value;
          span.addEventListener('click', function () { handleCopyClick(this, this.dataset.copy); });
          line.appendChild(span);
        } else {
          line.appendChild(document.createTextNode(value));
        }
        return line;
      };

      detail.append(
        makeLine('主 NS', primaryNs, true),
        makeLine('管理邮箱', adminEmail, true),
        makeLine('序列号', parts[2] || '', false),
        makeLine('刷新间隔', formatTTL(parts[3]), false),
        makeLine('重试间隔', formatTTL(parts[4]), false),
        makeLine('过期时间', formatTTL(parts[5]), false),
        makeLine('最小 TTL', formatTTL(parts[6]), false)
      );

      row.append(header, detail);
      return row;
    }

    // ── 渲染结果 ──────────────────────────────────────────────────────────────
    function displayRecords(data) {
      document.getElementById('resultContainer').style.display = 'block';
      document.getElementById('errorContainer').style.display = 'none';
      document.getElementById('result').textContent = JSON.stringify(data, null, 2);
      document.getElementById('copyBtn').style.display = 'block';

      // IPv4
      const ipv4Records = data.ipv4?.records || [];
      const ipv4Container = document.getElementById('ipv4Records');
      ipv4Container.innerHTML = '';
      document.getElementById('ipv4Summary').textContent =
        ipv4Records.length ? '找到 ' + ipv4Records.length + ' 条 IPv4 记录' : '未找到 IPv4 记录';

      ipv4Records.forEach(r => {
        if (r.type === 5) ipv4Container.appendChild(buildCnameRow(r.data, r.TTL));
        else if (r.type === 1) ipv4Container.appendChild(buildIpRecordRow(r.data, 1, r.TTL));
      });

      // IPv6
      const ipv6Records = data.ipv6?.records || [];
      const ipv6Container = document.getElementById('ipv6Records');
      ipv6Container.innerHTML = '';
      document.getElementById('ipv6Summary').textContent =
        ipv6Records.length ? '找到 ' + ipv6Records.length + ' 条 IPv6 记录' : '未找到 IPv6 记录';

      ipv6Records.forEach(r => {
        if (r.type === 5) ipv6Container.appendChild(buildCnameRow(r.data, r.TTL));
        else if (r.type === 28) ipv6Container.appendChild(buildIpRecordRow(r.data, 28, r.TTL));
      });

      // NS
      const nsRecords = data.ns?.records || [];
      const nsContainer = document.getElementById('nsRecords');
      nsContainer.innerHTML = '';
      document.getElementById('nsSummary').textContent =
        nsRecords.length ? '找到 ' + nsRecords.length + ' 条名称服务器记录' : '未找到 NS 记录';

      nsRecords.forEach(r => {
        if (r.type === 2) nsContainer.appendChild(buildNsRow(r.data, r.TTL));
        else if (r.type === 6) nsContainer.appendChild(buildSoaRow(r));
      });
    }

    function displayError(message) {
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('errorContainer').style.display = 'block';
      document.getElementById('errorMessage').textContent = message;
      document.getElementById('copyBtn').style.display = 'none';
    }

    // ── 表单提交 ──────────────────────────────────────────────────────────────
    document.getElementById('resolveForm').addEventListener('submit', async function (e) {
      e.preventDefault();

      const dohSelect = document.getElementById('dohSelect').value;
      let doh;
      if (dohSelect === 'current') {
        doh = currentDohUrl;
      } else if (dohSelect === 'custom') {
        doh = document.getElementById('customDoh').value.trim();
        if (!doh) { alert('请输入自定义 DoH 地址'); return; }
      } else {
        doh = dohSelect;
      }

      const domain = document.getElementById('domain').value.trim();
      if (!domain) { alert('请输入需要解析的域名'); return; }

      document.getElementById('loading').style.display = 'block';
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('errorContainer').style.display = 'none';
      document.getElementById('copyBtn').style.display = 'none';

      try {
        const resp = await fetch('?doh=' + encodeURIComponent(doh) + '&domain=' + encodeURIComponent(domain) + '&type=all');
        if (!resp.ok) throw new Error('HTTP 错误: ' + resp.status);
        const json = await resp.json();
        if (json.error) displayError(json.error);
        else displayRecords(json);
      } catch (err) {
        displayError('查询失败: ' + err.message);
      } finally {
        document.getElementById('loading').style.display = 'none';
      }
    });

    // ── DoH 下拉切换 ──────────────────────────────────────────────────────────
    document.getElementById('dohSelect').addEventListener('change', function () {
      document.getElementById('customDohContainer').style.display =
        this.value === 'custom' ? 'block' : 'none';
    });

    // ── 清除按钮 ──────────────────────────────────────────────────────────────
    document.getElementById('clearBtn').addEventListener('click', function () {
      document.getElementById('domain').value = '';
      document.getElementById('domain').focus();
    });

    // ── 复制结果按钮 ──────────────────────────────────────────────────────────
    document.getElementById('copyBtn').addEventListener('click', function () {
      const text = document.getElementById('result').textContent;
      navigator.clipboard.writeText(text).then(() => {
        const orig = this.textContent;
        this.textContent = '已复制';
        setTimeout(() => { this.textContent = orig; }, 2000);
      }).catch(e => console.error('复制失败:', e));
    });

    // ── Get Json 按钮 ─────────────────────────────────────────────────────────
    document.getElementById('getJsonBtn').addEventListener('click', function () {
      const dohSelect = document.getElementById('dohSelect').value;
      let dohUrl;
      if (dohSelect === 'current') {
        dohUrl = currentDohUrl;
      } else if (dohSelect === 'custom') {
        dohUrl = document.getElementById('customDoh').value.trim();
        if (!dohUrl) { alert('请输入自定义 DoH 地址'); return; }
      } else {
        dohUrl = dohSelect;
      }

      const domain = document.getElementById('domain').value.trim();
      if (!domain) { alert('请输入需要解析的域名'); return; }

      const jsonUrl = new URL(dohUrl);
      jsonUrl.searchParams.set('name', domain);
      window.open(jsonUrl.toString(), '_blank');
    });

    // ── 页面初始化 ────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', function () {
      // 记住上次输入的域名
      const lastDomain = localStorage.getItem('lastDomain');
      if (lastDomain) document.getElementById('domain').value = lastDomain;

      document.getElementById('domain').addEventListener('input', function () {
        localStorage.setItem('lastDomain', this.value);
      });

      // 更新页脚和下拉框中的当前站点信息
      document.getElementById('currentDomain').textContent = currentHost;
      const currentDohOption = document.getElementById('currentDohOption');
      if (currentDohOption) currentDohOption.textContent = currentDohUrl + ' (当前站点)';

      // DoH 链接点击复制
      const dohUrlDisplay = document.getElementById('dohUrlDisplay');
      if (dohUrlDisplay) {
        dohUrlDisplay.addEventListener('click', function () {
          navigator.clipboard.writeText(currentDohUrl).then(() => {
            dohUrlDisplay.classList.add('copied');
            setTimeout(() => dohUrlDisplay.classList.remove('copied'), 2000);
          }).catch(e => console.error('复制失败:', e));
        });
      }
    });
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" }
  });
}

// ─── URL 代理 ─────────────────────────────────────────────────────────────────

async function proxyURL(proxyTarget, targetUrl) {
  const urlList = await parseURLList(proxyTarget);
  const fullUrl = urlList[Math.floor(Math.random() * urlList.length)];
  const parsed = new URL(fullUrl);

  const protocol = parsed.protocol.slice(0, -1) || 'https';
  const hostname = parsed.hostname;
  let pathname = parsed.pathname;
  const search = parsed.search;

  if (pathname.endsWith('/')) pathname = pathname.slice(0, -1);
  pathname += targetUrl.pathname;

  const newUrl = `${protocol}://${hostname}${pathname}${search}`;
  const response = await fetch(newUrl);

  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });
  newResponse.headers.set('X-New-URL', newUrl);
  return newResponse;
}

async function parseURLList(content) {
  let normalized = content.replace(/[\t|"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (normalized.startsWith(','))  normalized = normalized.slice(1);
  if (normalized.endsWith(','))    normalized = normalized.slice(0, -1);
  return normalized.split(',');
}

// ─── Nginx 伪装页 ─────────────────────────────────────────────────────────────

async function nginx() {
  return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
  body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.
Further configuration is required.</p>
<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}
