import './style.css'

document.getElementById('btnSign').addEventListener('click', () => signWithPrivate());
document.getElementById('btnVerify').addEventListener('click', () => verifyWithPublic());

export function signWithPrivate() {
  const privateStr = (document.getElementById('private') as any).value;
  const dataStr = (document.getElementById('data') as any).value;

  importRsaKey(privateStr, 'PRIVATE', 'RSASSA-PKCS1-v1_5', 'SHA-256', ['sign'])
    .then(key => {
      console.log('private key to sign: ', key);
      return signWithPrivateKey(key, dataStr);
    })
    .then(d => {
      console.log('signature generated: ', d.signatureString);
      (document.getElementById('signature') as any).value = d.signatureString;
    });
}

export function verifyWithPublic() {
  const publicStr = (document.getElementById('public') as any).value;
  const dataStr = (document.getElementById('data') as any).value;
  const signatureStr = (document.getElementById('signature') as any).value;

  importRsaKey(publicStr, 'PUBLIC', 'RSASSA-PKCS1-v1_5', 'SHA-256', ['verify'])
    .then(key => {
      console.log('public key to verify: ', key);
      return verifyWithPublicKey(key, dataStr, signatureStr);
    })
    .then(d => {
      (document.getElementById('verification') as any).innerHTML = d ? '<b style="color: green;">VERIFIED !!</b>' : '<b style="color: red;">VERIFICATION FAILED.. on va y arriver julien!! courage !!!</b>';
    });
}

////////////////////////////////////////////////
////////////////////////////////////////////////
////////////////////////////////////////////////


export function importRsaKey(pem: string, type: 'PUBLIC' | 'PRIVATE', algorithmName: string, algorithmHash: string, keyUsages: Array<KeyUsage>): Promise<CryptoKey> {
    const key = pemToArrayBuffer(pem, type);
    const format = (type === 'PUBLIC') ? 'spki' : 'pkcs8';

    return (window.crypto.subtle.importKey(format, key, {name: algorithmName, hash: algorithmHash}, false, keyUsages) as Promise<CryptoKey>);
}

function pemToArrayBuffer(pem: string, type: 'PUBLIC' | 'PRIVATE'): ArrayBuffer {
    const b64Lines = removeLines(pem);
    const b64Prefix = b64Lines.replace(`-----BEGIN ${ type } KEY-----`, '');
    const b64Final = b64Prefix.replace(`-----END ${ type } KEY-----`, '');

    return base64ToArrayBuffer(b64Final);
}

function removeLines(str: string): string {
    return str.replace('\n', '');
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
    const byteString = window.atob(b64);
    const byteArray = new Uint8Array(byteString.length);
    for(let i=0; i < byteString.length; i++) {
        byteArray[i] = byteString.charCodeAt(i);
    }

    return byteArray;
}

///////////////////////////////////////

function signWithPrivateKey(key: CryptoKey, plaintext: string): Promise<{signatureBytes: Uint8Array, signatureString: string}> {
    const plaintextBytes = (new TextEncoder()).encode(plaintext);

    return (window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, plaintextBytes) as Promise<ArrayBuffer>)
        .then(signatureBytes => new Uint8Array(signatureBytes))
        .then(signatureBytes => ({
            signatureBytes,
            signatureString: toHexString(signatureBytes),
        }));
}

function verifyWithPublicKey(key: CryptoKey, plaintext: string, signature: string): Promise<boolean> {
    const plaintextBytes = (new TextEncoder()).encode(plaintext);
    const signatureBytes = toByteArray(signature);

    return (window.crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signatureBytes, plaintextBytes) as Promise<boolean>);
}

///////////////////////////////////////

function toHexString(byteArray: Uint8Array): string {
    return Array.prototype.map.call(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function toByteArray(hexString: string): Uint8Array {
    const result = [];
    for (let i = 0; i < hexString.length; i += 2) {
        result.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(result);
}

///////////////////////////////////////

(document.getElementById('data') as any).value = '{"name":"sdvsdv","access":{"key_id":65,"key":{"value":"296d77d30dac772275bb4e4ee542183efa1b0293c14e51d338619bb50d14fdd37d44b3b8506fb8abb3aaa10f293ba569348f3a1e21589a42865ec4bb40bd31789b663f165b0171b63fb6d487d4e08bbb3b439e35db8818c3cdaaa99108fad116f8fe5f05d59084bd556dd225c51e25844f74fefe9bb8cb8b540c07a4c35cdc3c91e341152584c58e756c888ea74a6ebac3325060520ccd255da7712eca6c9eb8f6b842516ecd7a4b3453ebbd4d35aad46c429a9defc49f0d4d96346f56982a5f8ff4337cb851ceaab6ae5d3cd763e90c4e6720d42984e6315fd240dcd3e2df82b4a5c85a2a173cdbef29d414920689870e21e54351d134ed43be49a12ac1369a","meta":{"alg":"AES-GCM","length":256}}}}';

(document.getElementById('public') as any).value = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvf0+AoPvhtTh/gDst88u
oROlkZTE8qDcfZQ2SxKMmnOOPS7I4aaJWi36zuzY2ZvUE0dgv0mcy62r/jkc2u7y
NMIR1tzjkR+xsmL7XKngX9ZXKRsJ9Y2cnxgqsCtzWYjzvqj26xnlusXOAOQ+RRsG
WcFG/6KipoHv/gWdfObkNXTA5f79ab9ciZuMtytnzLyMgNBy59zEC+EN6LiXUAYG
zZvy/PIHW38YK6EWQC4xqojU2cEsqs1g0XJtNRQhd4w6x+bYSOEesV/pbxl8KUkK
zdcxIQs/iprk+WXCjNXGUCFE0V19ssqFYll0PFq2YwkyaJEti1roBEeSTOMia7g0
gQIDAQAB
-----END PUBLIC KEY-----`;

(document.getElementById('private') as any).value = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9/T4Cg++G1OH+
AOy3zy6hE6WRlMTyoNx9lDZLEoyac449LsjhpolaLfrO7NjZm9QTR2C/SZzLrav+
ORza7vI0whHW3OORH7GyYvtcqeBf1lcpGwn1jZyfGCqwK3NZiPO+qPbrGeW6xc4A
5D5FGwZZwUb/oqKmge/+BZ185uQ1dMDl/v1pv1yJm4y3K2fMvIyA0HLn3MQL4Q3o
uJdQBgbNm/L88gdbfxgroRZALjGqiNTZwSyqzWDRcm01FCF3jDrH5thI4R6xX+lv
GXwpSQrN1zEhCz+KmuT5ZcKM1cZQIUTRXX2yyoViWXQ8WrZjCTJokS2LWugER5JM
4yJruDSBAgMBAAECggEADuIdz3iidP+MTKep46RZVMkDOWpcG126qCPKNQtY9GiF
Bgn6NqMjM2tSsI8hVbq9XF1FGPcdT19lj97NgeEiHDvvxdM8CIxhEUZrxpCQQTG7
Vj8GArR7RoNQJMjimmr+HTuDTFuVAZKpVqyKrEM3tiRL+Y62CzE2qcGq2rQDwKQo
KCMerymsXDAozXvPrcAGmXG4CuPVBv6gXcOXLYwjQC9tNGqb3WlJmec3F+gZFRPR
X6lcOCkaIr2+roqYYcse8TqG26Alf2aIxiKxpvv9jHrGD+6BMfJ+y0DHcxVWYv/t
t4HDlPLfznsvHeBsfeI0jRgYU02UY2aP9T8vP8GZmQKBgQDuTdwR79gUm13m/ZW6
E6earhxNtUzahr9F2pB0FU2mhB4U9hgzu39n7hUscjtSobeV+usKKBJ6vUy9P6WM
VclX5dskKwXsRoqDQhn/0f/hwxcNNMuLLsnt3ShNZMQjcA/v6ZbmtEwQL/3MwHG6
v7XPNMv2RUQk9U0ju0wGFJ8j8wKBgQDMGOuhQ9ValifbfuoW9QhcjsYFpz/V1SFq
F7uWW5CLjXjPxgmU/sgwh7P0OExghYgF874bQSSx1FPjzXo0YIO44V/E9oN7Cphb
eLexT+x8sJS7X5rmGZze453CWjFGtd4JPZEuccGJX68+6rrj/L8SQjLYXQfrABJM
eLOCHWnGuwKBgAzeUXr6e62pMinuGa7BrvRQYKDloG/QhPWtts099UJ/sewp2ea5
QkkHd0c+J+vvZa2IrjaPMWhFXqZ9kGACpevEMtBCLoCy0noCEMtauLmlQlJpPnCW
pzrcDXgYb+sF+yZWc9qjc9QP82GiJsIR5ix5SmZTGTnxsSezzogphup3AoGBAKmp
zbcxfJrhWCDPUCnlaB4JUfRBJH/NvQlE0Vwcofxgjp2qMyz439H3/VB3vIZAeuL3
zIE7lhV+PH6SwZPo55c5QzOo+YO/OwhPQeTUW/MLl5hr0YiWoiFndi2qbGwro3hr
BdVmG0znjfbvio0b/npfLYVPUNW6KXwImrD/Yn8hAoGATMguYYQKoEaOuMlr1EjW
TenZDalHMwfImbXh8URwkB47Jo3p7Tu7plDM1dwY7XT4T8eurHgAG3bod2wZ2bZl
y/VZsCUWaemjdaasLnAS7BBHSqFM2kikYXYmeAQCnw5kkF9Rlps6Xalue8PmWT1x
mrniGfiNlIj4cF6z1rk6cGs=
-----END PRIVATE KEY-----`;