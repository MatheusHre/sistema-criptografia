"""CryptoTool: implementação acadêmica de Fernet, RSA-OAEP e SHA-256."""
from pathlib import Path
import argparse
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class CryptoTool:
    @staticmethod
    def gerar_chave_simetrica(chave_path='chave_simetrica.key'):
        Path(chave_path).write_bytes(Fernet.generate_key())

    @staticmethod
    def gerar_par_chaves_assimetricas(priv_path='privada.pem', pub_path='publica.pem'):
        privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        Path(priv_path).write_bytes(privada.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        Path(pub_path).write_bytes(privada.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    @staticmethod
    def criptografar_simetrico(arquivo, chave_path='chave_simetrica.key', saida=None):
        destino = Path(saida or str(arquivo)+'.sim')
        token = Fernet(Path(chave_path).read_bytes()).encrypt(Path(arquivo).read_bytes())
        destino.write_bytes(token)
        return destino

    @staticmethod
    def descriptografar_simetrico(arquivo, chave_path='chave_simetrica.key', saida=None):
        destino = Path(saida or str(arquivo)+'.dec')
        dados = Fernet(Path(chave_path).read_bytes()).decrypt(Path(arquivo).read_bytes())
        destino.write_bytes(dados)
        return destino

    @staticmethod
    def _oaep():
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    @staticmethod
    def criptografar_assimetrico(arquivo, pub_path='publica.pem', saida=None):
        publica = serialization.load_pem_public_key(Path(pub_path).read_bytes())
        dados = Path(arquivo).read_bytes()
        limite = publica.key_size//8 - 2*hashes.SHA256().digest_size - 2
        if len(dados) > limite:
            raise ValueError(f'RSA direto aceita no máximo {limite} bytes nesta configuração.')
        cifrado = publica.encrypt(dados, CryptoTool._oaep())
        destino = Path(saida or str(arquivo)+'.asi')
        destino.write_bytes(cifrado)
        return destino

    @staticmethod
    def descriptografar_assimetrico(arquivo, priv_path='privada.pem', saida=None):
        privada = serialization.load_pem_private_key(Path(priv_path).read_bytes(), password=None)
        dados = privada.decrypt(Path(arquivo).read_bytes(), CryptoTool._oaep())
        destino = Path(saida or str(arquivo)+'.dec')
        destino.write_bytes(dados)
        return destino

    @staticmethod
    def gerar_hash(arquivo, saida=None):
        resumo = hashlib.sha256()
        with Path(arquivo).open('rb') as entrada:
            for bloco in iter(lambda: entrada.read(65536), b''):
                resumo.update(bloco)
        destino = Path(saida or str(arquivo)+'.has')
        destino.write_text(resumo.hexdigest()+'\n', encoding='ascii')
        return destino

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operacao', choices=['chave-sim','chaves-rsa','cifrar-sim','decifrar-sim','cifrar-rsa','decifrar-rsa','hash'])
    parser.add_argument('arquivo', nargs='?')
    parser.add_argument('--chave', default='chave_simetrica.key')
    parser.add_argument('--publica', default='publica.pem')
    parser.add_argument('--privada', default='privada.pem')
    parser.add_argument('--saida')
    args = parser.parse_args()
    try:
        if args.operacao == 'chave-sim':
            CryptoTool.gerar_chave_simetrica(args.chave)
        elif args.operacao == 'chaves-rsa':
            CryptoTool.gerar_par_chaves_assimetricas(args.privada, args.publica)
        else:
            if not args.arquivo:
                parser.error('Informe o arquivo de entrada.')
            funcoes = {'cifrar-sim': (CryptoTool.criptografar_simetrico,args.chave), 'decifrar-sim': (CryptoTool.descriptografar_simetrico,args.chave), 'cifrar-rsa': (CryptoTool.criptografar_assimetrico,args.publica), 'decifrar-rsa': (CryptoTool.descriptografar_assimetrico,args.privada)}
            if args.operacao == 'hash':
                print(CryptoTool.gerar_hash(args.arquivo,args.saida))
            else:
                funcao,chave = funcoes[args.operacao]
                print(funcao(args.arquivo,chave,args.saida))
    except (OSError, ValueError, InvalidToken) as erro:
        parser.exit(1, f'Erro: {str(erro) or "Chave incorreta ou arquivo inválido."}\n')

if __name__ == '__main__':
    main()
