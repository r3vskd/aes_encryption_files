#include <iostream>
#include <fstream>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
namespace fs = std::filesystem;

void encryptFile(const std::string& inputFile, const std::string& outputFile, const SecByteBlock& key, const byte* iv)
{
    CCM<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv, iv ? AES::BLOCKSIZE : 0);
    
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);
    
    AuthenticatedEncryptionFilter ef(encryptor, new FileSink(out), false);
    ef.ChannelPut("", iv ? iv : NULL, iv ? AES::BLOCKSIZE : 0);
    FileSource fs(in, true, new StreamTransformationFilter(ef));
}

void encryptFolder(const std::string& inputFolder, const std::string& outputFolder, const SecByteBlock& key, const byte* iv)
{
    for (const auto& entry : fs::recursive_directory_iterator(inputFolder)) {
        if (entry.is_directory()) {
            // Create corresponding directory structure in output folder
            const std::string& relPath = entry.path().string().substr(inputFolder.size());
            const std::string& outputPath = outputFolder + relPath;
            fs::create_directories(outputPath);
        } else if (entry.is_regular_file()) {
            // Encrypt the file and write to output folder
            const std::string& relPath = entry.path().string().substr(inputFolder.size());
            const std::string& outputPath = outputFolder + relPath + ".enc";
            encryptFile(entry.path().string(), outputPath, key, iv);
        }
    }
}

int main()
{
    const std::string inputPath = "/path/to/input";
    const std::string outputPath = "/path/to/output";
    const std::string passphrase = "mysecret";

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)passphrase.data(), passphrase.size(), nullptr, 0);

    byte iv[AES::BLOCKSIZE];
    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, sizeof(iv));

    encryptFolder(inputPath, outputPath, key, iv);

    return 0;
}
