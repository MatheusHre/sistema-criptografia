# CryptoTool

Versão desenvolvida a partir da proposta acadêmica com Fernet, RSA e SHA-256.

## Instalação

```sh
python -m pip install -r requirements.txt
python crypto_tool.py chave-sim
python crypto_tool.py chaves-rsa
python crypto_tool.py cifrar-sim exemplo.txt
python crypto_tool.py decifrar-sim exemplo.txt.sim --saida recuperado_sim.txt
python crypto_tool.py cifrar-rsa exemplo.txt
python crypto_tool.py decifrar-rsa exemplo.txt.asi --saida recuperado_rsa.txt
python crypto_tool.py hash exemplo.txt
python -m unittest discover -s . -v
```
## Testes
14 testes passaram em 15/09/2026. Consulte testes_resultado.txt.
