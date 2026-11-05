# secretsweep

掃描資料夾，找出不小心寫進程式碼的 API key、token、私鑰等機密資料。
只用 Python 標準函式庫，沒有任何外部相依套件。

*Scan files for accidentally committed secrets. Zero dependencies.*

## 安裝

```bash
pip install git+https://github.com/wrm37056-cpu/leakscan.git
```

## 使用

```bash
secretsweep            # 掃描目前資料夾
secretsweep src/ app.py
python -m secretsweep .
```

輸出只會顯示**檔案、行號、類型**，不會印出機密本身（避免機密再外洩到 CI log）。
有找到就回傳 exit code 1，所以可以直接放進 CI 或 git pre-commit hook。

## 偵測項目

| 類型 | 說明 |
|---|---|
| AWS access key | `AKIA` 開頭的 20 碼金鑰 |
| GitHub token | `ghp_` / `gho_` 等開頭的 token |
| Slack token | `xoxb-` 等開頭的 token |
| Private key | PEM 格式私鑰標頭 |
| Generic secret | `api_key` / `password` / `token` 等變數被指定成字串常數 |

## 開發

```bash
python -m unittest -v
```

## 回報漏洞

請看 [SECURITY.md](SECURITY.md)。

## 授權

MIT
