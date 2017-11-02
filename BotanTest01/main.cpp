#include <QtCore/QCoreApplication>
#include <botan/botan.h>

#include <QDebug>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <memory>

using namespace std;
using namespace Botan;

void Encrypt(SymmetricKey key, InitializationVector iv, string inFilename,  string outFilename)
{
    std::ifstream in(inFilename.c_str(),std::ios::binary);
    std::ofstream out(outFilename.c_str(),std::ios::binary);

    Pipe pipe(get_cipher("AES-256/CBC", key, iv,ENCRYPTION),new DataSink_Stream(out));
    pipe.start_msg();
    in >> pipe;
    pipe.end_msg();

    out.flush();
    out.close();
    in.close();

    qDebug() << "Encrypted!";
}

void Decrypt(SymmetricKey key, InitializationVector iv, string inFilename,  string outFilename)
{
    std::ifstream in(inFilename.c_str(),std::ios::binary);
    std::ofstream out(outFilename.c_str(),std::ios::binary);

    Pipe pipe(get_cipher("AES-256/CBC", key, iv,DECRYPTION),new DataSink_Stream(out));
    pipe.start_msg();
    in >> pipe;
    pipe.end_msg();

    out.flush();
    out.close();
    in.close();

    qDebug() << "Decrypted!";
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qDebug() << "Starting Botan";

    string filePlainText = "E:\\Test\\ZZZ\\plaintext.txt";
    string fileEncrypted = "E:\\Test\\ZZZ\\encrypted.txt";
    string fileDecrypted = "E:\\Test\\ZZZ\\decrypted.txt";

    Botan::LibraryInitializer init;

    string passphrase = "mypassword";
    AutoSeeded_RNG rng;
    S2K* s2k = get_s2k("PBKDF2(SHA-256)");
    s2k->set_iterations(4049);

    SecureVector<byte> key_and_IV = s2k->derive_key(48, passphrase).bits_of();
    SymmetricKey key(key_and_IV, 32);
    InitializationVector iv(key_and_IV +32, 16);

    Encrypt(key,iv,filePlainText,fileEncrypted);
    Decrypt(key,iv,fileEncrypted,fileDecrypted);

    return a.exec();
}

void main2()
{
    try
    {
        qDebug() << "Starting BOTAN";

        QString sItem = "";
        //sItem.toStdString()


        string filePlainText = "c:\\test\\plaintext.txt";
        string fileEncoded = "c:\\test\\encoded.txt";
        string fileDecoded = "c:\\test\\decoded.txt";

        string fileEncrypted = "c:\\test\\encrypted.txt";
        string fileDecrypted = "c:\\test\\decrypted.txt";

        Botan::LibraryInitializer init;

//        AutoSeeded_RNG rng;
//        SymmetricKey key(rng, 16); // a random 128-bit key
//        InitializationVector iv(rng, 16); // a random 128-bit IV

//        Encode(filePlainText, fileEncoded);
//        Decode(fileEncoded,fileDecoded);


        string passphrase = "password";
        AutoSeeded_RNG rng;
        S2K* s2k = get_s2k("PBKDF2(SHA-256)");
        // hard-coded iteration count for simplicity; should be sufficient
        s2k->set_iterations(4096);
        // 8 octets == 64-bit salt; again, good enough
        //s2k->new_random_salt(rng,8);
        //SecureVector<byte> the_salt = s2k->current_salt();
        // 48 octets == 32 for key + 16 for IV
        SecureVector<byte> key_and_IV = s2k->derive_key(48, passphrase).bits_of();
        SymmetricKey key(key_and_IV, 32);
        InitializationVector iv(key_and_IV + 32, 16);

        //Encrypt(key,iv,filePlainText,fileEncrypted);
        Decrypt(key,iv,fileEncrypted,fileDecrypted);

        qDebug() << "Done";
    }
    catch(std::exception& e)
    {
        std::cerr << e.what() << "\n";
    }
}
