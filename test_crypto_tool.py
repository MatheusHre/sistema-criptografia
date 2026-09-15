import unittest
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from crypto_tool import CryptoTool as C

class TestCryptoTool(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.p=Path(self.tmp.name); self.f=self.p/'entrada.txt'; self.f.write_bytes('Criptografia acadêmica'.encode())
        self.k=self.p/'chave.key'; self.pr=self.p/'privada.pem'; self.pu=self.p/'publica.pem'
        C.gerar_chave_simetrica(self.k); C.gerar_par_chaves_assimetricas(self.pr,self.pu)
    def test_01_chave_fernet(self):
        self.assertEqual(Fernet(self.k.read_bytes()).decrypt(Fernet(self.k.read_bytes()).encrypt(b'abc')),b'abc')
    def test_02_par_rsa(self):
        pr=serialization.load_pem_private_key(self.pr.read_bytes(),None); pu=serialization.load_pem_public_key(self.pu.read_bytes())
        self.assertEqual(pr.key_size,2048); self.assertEqual(pr.public_key().public_numbers(),pu.public_numbers())
    def test_03_sim_texto(self):
        s=C.criptografar_simetrico(self.f,self.k); self.assertEqual(s.suffix,'.sim'); self.assertEqual(C.descriptografar_simetrico(s,self.k).read_bytes(),self.f.read_bytes())
    def test_04_sim_binario(self):
        self.f.write_bytes(bytes(range(256))*256); s=C.criptografar_simetrico(self.f,self.k); self.assertEqual(C.descriptografar_simetrico(s,self.k).read_bytes(),self.f.read_bytes())
    def test_05_sim_vazio(self):
        self.f.write_bytes(b''); s=C.criptografar_simetrico(self.f,self.k); self.assertEqual(C.descriptografar_simetrico(s,self.k).read_bytes(),b'')
    def test_06_sim_chave_errada(self):
        s=C.criptografar_simetrico(self.f,self.k); C.gerar_chave_simetrica(self.k)
        with self.assertRaises(InvalidToken): C.descriptografar_simetrico(s,self.k)
        self.assertFalse(Path(str(s)+'.dec').exists())
    def test_07_sim_adulterado(self):
        s=C.criptografar_simetrico(self.f,self.k); s.write_bytes(b'invalido')
        with self.assertRaises(InvalidToken): C.descriptografar_simetrico(s,self.k)
    def test_08_rsa_texto(self):
        s=C.criptografar_assimetrico(self.f,self.pu); self.assertEqual(s.suffix,'.asi'); self.assertEqual(len(s.read_bytes()),256); self.assertEqual(C.descriptografar_assimetrico(s,self.pr).read_bytes(),self.f.read_bytes())
    def test_09_rsa_limite(self):
        self.f.write_bytes(b'a'*190); s=C.criptografar_assimetrico(self.f,self.pu); self.assertEqual(C.descriptografar_assimetrico(s,self.pr).read_bytes(),self.f.read_bytes())
    def test_10_rsa_excesso(self):
        self.f.write_bytes(b'a'*191)
        with self.assertRaises(ValueError): C.criptografar_assimetrico(self.f,self.pu)
        self.assertFalse(Path(str(self.f)+'.asi').exists())
    def test_11_rsa_chave_errada(self):
        s=C.criptografar_assimetrico(self.f,self.pu); C.gerar_par_chaves_assimetricas(self.pr,self.pu)
        with self.assertRaises(ValueError): C.descriptografar_assimetrico(s,self.pr)
    def test_12_hash_vetor(self):
        self.f.write_bytes(b'abc'); s=C.gerar_hash(self.f); self.assertEqual(s.suffix,'.has'); self.assertEqual(s.read_text().strip(),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    def test_13_hash_alteracao(self):
        a=C.gerar_hash(self.f).read_text(); self.f.write_bytes(self.f.read_bytes()+b'!'); self.assertNotEqual(a,C.gerar_hash(self.f).read_text())
    def test_14_arquivo_ausente(self):
        with self.assertRaises(FileNotFoundError): C.gerar_hash(self.p/'ausente')
if __name__=='__main__': unittest.main(verbosity=2)
