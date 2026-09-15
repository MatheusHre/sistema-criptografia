# CryptoTool

Versão de referência reconstruída a partir da proposta acadêmica com Fernet, RSA e SHA-256.

## Instalação
Python 3. Ambiente validado: Python 3.12.14, cryptography 46.0.0, Linux.

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

## Limitações
RSA direto: até 190 bytes por arquivo com RSA 2048 e OAEP SHA-256. Saída RSA: 256 bytes. Fernet carrega o arquivo em memória. Chave privada PEM sem senha. Arquivos existentes podem ser sobrescritos. Hash simples não comprova autoria. Não publicar as chaves.

## Testes
14 testes passaram em 15/09/2026. Consulte testes_resultado.txt. Não houve teste automatizado da CLI ou benchmark.

## Publicação do código-fonte
Crie um repositório no GitHub ou serviço escolhido e envie os arquivos deste pacote. Não envie chave_simetrica.key nem privada.pem. Copie a URL real do repositório para o campo de link público no Word e no último slide. O pacote ZIP permite acesso ao código, mas não substitui a URL pública exigida.
