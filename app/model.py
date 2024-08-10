from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import zipfile
from abc import ABC, abstractmethod
from utils.exceptions import INVALIDKEYORALGORITHM
from eventemitter import EventEmitter
from typing import Callable, Self
from enum import Enum


class EncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        pass


class FernetEncryptionStrategy(EncryptionStrategy):

    '''
    Fernet is a high-level symmetric encryption method provided by the cryptography library in Python. It is designed to be easy to use and provides both encryption and authentication. It ensures that data is not only encrypted but also authenticated, preventing tampering.
    Features:
        - Authenticated Encryption: Ensures data integrity and authenticity (prevents tampering).
        - Ease of Use: Provides a simple API for encryption and decryption.
        - Key Size: 32 bytes.
        - Block Size: Uses AES under the hood with CBC mode and HMAC for authentication.
    '''

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        try:
            encryptor = Fernet(key)
        except InvalidToken:
            raise INVALIDKEYORALGORITHM()

        return encryptor.encrypt(data)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        try:
            decryptor = Fernet(key)
        except InvalidToken:
            raise INVALIDKEYORALGORITHM()
        return decryptor.decrypt(data)


class AESEncryptionStrategy(EncryptionStrategy):
    '''
    AES is a low-level encryption algorithm provided by various cryptographic libraries. It is highly configurable and can be used in different modes of operation like CBC (Cipher Block Chaining), GCM (Galois/Counter Mode), etc. AES requires careful handling of initialization vectors (IVs) and padding.
    '''

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        # generate a random IV
        iv = os.urandom(16)

        # Create an AES cipher objec with the key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        # pad the data to be a multiple of the AES block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data: bytes = padder.update(data) + padder.finalize()

        # encrypt the padded data
        encrypted_data: bytes = encryptor.update(
            padded_data)+encryptor.finalize()

        # Prepend the IV to the encrypted data because the IV needed for decryption.
        encrypted_data_with_iv: bytes = iv+encrypted_data
        return encrypted_data_with_iv

    def decrypt(self, data: bytes, key: bytes) -> bytes:

        # get the first 16 bytes which is the iv appended by the encryptor
        iv = data[:16]

        # get the actual encrypted data part
        encrypted_data = data[16:]

        # Create an AES sipher object with the key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        # decrypt the data
        padded_data: bytes = decryptor.update(data)+decryptor.finalize()

        # unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpaded_data = unpadder.update(padded_data)+unpadder.finalize()
        return unpaded_data


class FileHandler(ABC):

    @abstractmethod
    def process(self, filePaths: list[str], outputPath: str, key: bytes, encryptionStrategy: EncryptionStrategy, progressCallback: Callable[[int], None]) -> None:
        pass

    def getProgress(self, numberOfFiles: int | float, total_files: int | float) -> int:
        return int(numberOfFiles*100/total_files)


class EncryptionFileHandler(FileHandler):
    pass


class DecryptionFileHandler(FileHandler):
    pass


class FileEncryptionHandler(EncryptionFileHandler):
    def process(self, filePaths: list[str], outputPath: str, key: bytes, encryptionStrategy: EncryptionStrategy, progressCallback: Callable[[int], None]) -> None:
        total_files = len(filePaths)
        for numberOfFiles, filePath in enumerate(filePaths, 1):
            outputFile = self.getoutputFileName(outputPath, filePath)
            with open(filePath, "rb") as inputFile, open(outputFile, "wb") as outputFile:
                data = inputFile.read()
                encryptedData = encryptionStrategy.encrypt(data, key)
                outputFile.write(encryptedData)
            progressCallback(self.getProgress(numberOfFiles, total_files))

    def getOutputFileName(self, outputPath: str, filePath: str) -> str:
        return os.path.abspath(outputPath+os.path.basename(filePath)+".enc")


class FileDecryptionHandler(DecryptionFileHandler):
    def process(self, filePaths: list[str], outputPath: str, key: bytes, encryptionStrategy: EncryptionStrategy, progressCallback: Callable[[int], None]) -> None:
        total_files = len(filePaths)
        for numberOfFiles, filePath in enumerate(filePaths, 1):
            outputFile = self.getOutputFileName(outputPath, filePath)
            with open(filePath, "rb") as inputFile, open(outputFile, "wb") as outputFile:
                data = inputFile.read()
                decryptedData = encryptionStrategy.decrypt(data, key)
                outputFile.write(decryptedData)
            progressCallback(self.getProgress(numberOfFiles, total_files))

    def getOutputFileName(self, outputPath: str, filePath: str) -> str:
        outputFileBaseName = os.path.basename(filePath).replace(".enc", "", 1)
        return os.path.abspath(outputPath+outputFileBaseName)


class ZipFileEncryptionHandler(FileHandler):
    zipFileName: str = "output.zip"

    def process(self, filePaths: list[str], outputPath: str, key: bytes, encryptionStrategy: EncryptionStrategy, progressCallback: Callable[[int], None]) -> None:
        total_files = len(filePaths)
        outputFile = self.getOutputZipFileName(outputPath)
        with zipfile.ZipFile(outputFile, "w") as zipFile:
            for numberOfFiles, filePath in enumerate(filePath, 1):
                with open(filePath, "rb") as inputFile:
                    data = inputFile.read()
                    encryptedData = encryptionStrategy.encrypt(data, key)
                    zipFile.writestr(self.getOutputFileName(
                        filePath), encryptedData)
                progressCallback(self.getProgress(numberOfFiles, total_files))

    def setOutputZipFileName(self, fileName: str):
        self.zipFileName = os.path.basename(fileName)

    def getOutputZipFileName(self, outputPath: str):
        return os.path.abspath(outputPath+self.zipFileName)

    def getOutputFileName(self, filePath: str) -> str:
        return os.path.basename(filePath+".enc")


class ZipFileDecryptionHandler(FileHandler):

    def process(self, filePaths: list[str], outputPath: str, key: bytes, encryptionStrategy: EncryptionStrategy, progressCallback: Callable[[int], None]) -> None:
        total_files = len(filePaths)
        for numberOfZipFiles, inputZipFile in enumerate(filePaths, 1):
            with zipfile.ZipFile(inputZipFile, 'r') as zip_file:
                file_list = [x for x in zip_file.namelist()
                             if x.endswith(".enc")]
                for fileName in file_list:
                    with zip_file.open(fileName) as inputFile:
                        data = inputFile.read()
                        decryptedData = encryptionStrategy.decrypt(data, key)
                        outputFileName = self.getOutputFileName(
                            outputPath, fileName)
                        with open(outputFileName, "wb") as outputFile:
                            outputFile.write(decryptedData)

            progressCallback(self.getProgress(numberOfZipFiles, total_files))

    def getOutputFileName(self, outputPath: str, filePath: str) -> str:
        outputFileBaseName = os.path.basename(filePath).replace(".enc", "", 1)
        return os.path.abspath(outputPath+outputFileBaseName)


class FileHandleFactory(ABC):
    @abstractmethod
    def createEncryptionHandler(self) -> EncryptionFileHandler:
        pass

    @abstractmethod
    def createDecryptionHandler(self) -> DecryptionFileHandler:
        pass


class FileHandleFactory(FileHandleFactory):
    def createEncryptionHandler(self) -> EncryptionFileHandler:
        return FileEncryptionHandler()

    def createDecryptionHandler(self) -> DecryptionFileHandler:
        return FileDecryptionHandler()


class ZipFileHandleFactory(FileHandleFactory):
    def createEncryptionHandler(self) -> EncryptionFileHandler:
        return ZipFileEncryptionHandler()

    def createDecryptionHandler(self) -> DecryptionFileHandler:
        return ZipFileDecryptionHandler()


class EventHandler(EventEmitter):

    _instance: EventEmitter = None

    def __new__(cls, *args, **kwargs) -> Self:
        if cls._instance is None:
            cls._instance = super(EventHandler, cls).__new__(cls)
        return cls._instance


class OutputFormats(Enum):
    ZIP: str = "zip"


class Operation(Enum):
    ENCRYPT: str = "encrypt"
    DECRYPT: str = "decrypt"


class EncryptionStrategies(Enum):
    FERNET:EncryptionStrategy = FernetEncryptionStrategy()
    AES:EncryptionStrategy = AESEncryptionStrategy()


class EncryptionModel:

    encryptionStrategy:EncryptionStrategy = AESEncryptionStrategy()

    def __init__(self) -> None:
        pass

    def generateKey(self, password: str, salt: str) -> bytes:

        # encode salt and password into bytes
        salt = salt.encode()
        password = password.encode()

        # create the key derivation function. (KDF) is a cryptographic algorithm that derives one or more secret keys from a secret value such as a master key, a password, or a passphrase using a pseudorandom function
        kdf = PBKDF2HMAC(
            # the algorithm is used to hash the password and salt to produce a key.
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            # Iterations refer to the number of times the KDF function performs its operations. Increasing the number of iterations makes the key derivation process slower, which increases resistance to brute-force attacks.
            iterations=10000,
            backend=default_backend()
        )

        # generate the key using key derivation function for the given password
        key = kdf.derive(password)

        # encode the key in url safe base64
        key = base64.urlsafe_b64encode(key)
        return key

    def processFiles(self, filePaths: list[str], outputPath: str, operation: Operation, password: str, outputFormat: OutputFormats, salt: str):
        key = self.generateKey(password, salt)

        factory: FileHandleFactory = None
        handler: FileHandler = None

        if outputFormat == OutputFormats.ZIP:
            factory = ZipFileHandleFactory()

        else:
            factory = FileHandleFactory()

        if operation == Operation.ENCRYPT:
            handler = factory.createEncryptionHandler()

        else:
            handler = factory.createDecryptionHandler()

        handler.process(filePaths, outputPath, key)

    def updateProgress(self,value):
        EventHandler().emit("encryptionDecryptionProgress",value)
    
    @classmethod
    def setStrategy(cls, encryptionStrategy:EncryptionStrategies):
        cls.encryptionStrategy = encryptionStrategy