#include "MainWindow.h"
#include <QFileDIalog>
#include <QFile>
#include <QTextStream>
#include <QTimer>

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::ArraySink;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi(this);
    QFont font;
    font.setFamily("Consolas");
    font.setPointSize(9);
    keyLineEdit->setFont(font);
    ivLineEdit->setFont(font);

    QIcon icoKey(":/icons/key.svg");
    QIcon icoIV(":/icons/iv.svg");
    keyLineEdit->setClearButtonEnabled(true);
    keyLineEdit->addAction(icoKey, QLineEdit::LeadingPosition);
    keyLineEdit->setPlaceholderText(QString::fromStdWString(L"Khóa bí mật ở dạng hex"));
    ivLineEdit->setClearButtonEnabled(true);
    ivLineEdit->addAction(icoIV, QLineEdit::LeadingPosition);
    ivLineEdit->setPlaceholderText(QString::fromStdWString(L"Vector khởi tạo ở dạng hex"));

    plainTextEdit->setPlaceholderText(QString::fromStdWString(L"Nội dung bản rõ"));
    cipherTextEdit->setPlaceholderText(QString::fromStdWString(L"Nội dung bản mã ở dạng hex"));
    recoveredTextEdit->setPlaceholderText(QString::fromStdWString(L"Nội dung bản giải mã"));

    mMessageLabel = new QLabel(this);
    Ui::MainWindowClass::statusBar->addWidget(mMessageLabel);

    mRNG = new AutoSeededRandomPool;
    mKeySizeList = new int[] {16, 24, 32};

    connect(generateKeyButton, &QPushButton::clicked, this, &MainWindow::generateKey);
    connect(generateKeyButton, &QPushButton::clicked, this, &MainWindow::generateIV);
    connect(keyLoadButton, &QPushButton::clicked, this, &MainWindow::loadKey);
    connect(ivLoadButton, &QPushButton::clicked, this, &MainWindow::loadIV);
    connect(keySaveButton, &QPushButton::clicked, this, &MainWindow::saveKey);
    connect(ivSaveButton, &QPushButton::clicked, this, &MainWindow::saveIV);

    connect(encryptButton, &QPushButton::clicked, this, &MainWindow::encrypt);
    connect(decryptButton, &QPushButton::clicked, this, &MainWindow::decrypt);

    connect(plainClearButton, &QPushButton::clicked, this, &MainWindow::clearPlainText);
    connect(cipherClearButton, &QPushButton::clicked, this, &MainWindow::clearCipherText);

    connect(plainLoadButton, &QPushButton::clicked, this, &MainWindow::loadPlainText);
    connect(cipherLoadButton, &QPushButton::clicked, this, &MainWindow::loadCipherText);
    connect(plainSaveButton, &QPushButton::clicked, this, &MainWindow::savePlainText);
    connect(cipherSaveButton, &QPushButton::clicked, this, &MainWindow::saveCipherText);
    connect(recoveredSaveButton, &QPushButton::clicked, this, &MainWindow::saveRecoveredText);

    connect(plainClearButton, &QPushButton::clicked, this, &MainWindow::clearPlainText);
    connect(cipherClearButton, &QPushButton::clicked, this, &MainWindow::clearCipherText);
    connect(recoveredClearButton, &QPushButton::clicked, this, &MainWindow::clearRecoveredText);
    connect(keyLineEdit, &QLineEdit::textChanged, this, &MainWindow::detectKeySize);
}

//Tạo khóa bí mật
void MainWindow::generateKey()
{
    int size = mKeySizeList[keySizeComboBox->currentIndex()];
    byte* key = new byte[size];
    mRNG->GenerateBlock(key, size);

    QString hexKey = dataToHex(key, size);
    keyLineEdit->setText(hexKey);

    setMessage(QString::fromStdWString(L"[i] Đã tạo khóa bí mật xong !"));
}

//Tạo vector khởi tạo
void MainWindow::generateIV()
{
    byte* iv = new byte[AES::BLOCKSIZE];
    mRNG->GenerateBlock(iv, AES::BLOCKSIZE);

    QString hexIV = dataToHex(iv, AES::BLOCKSIZE);
    ivLineEdit->setText(hexIV);
}

//Load khóa bí mật
void MainWindow::loadKey()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        QString::fromStdWString(L"Chọn khóa bí mật"),
        QString(), "Key files (*.key);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        std::string data;
        std::string file_name = fileName.toStdString();
        FileSource file(file_name.c_str(), true, new StringSink(data));
        QString key = dataToHex(data);
        keyLineEdit->setText(key);
        setMessage(QString::fromStdWString(L"[i] Đã tải vào khóa bí mật !"));
    }
}

// Load vector khởi tạo
void MainWindow::loadIV()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        QString::fromStdWString(L"Chọn vector khởi tạo"),
        QString(), "IV files (*.iv);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        std::string data;
        std::string file_name = fileName.toStdString();
        FileSource file(file_name.c_str(), true, new StringSink(data));
        QString iv = dataToHex(data);
        ivLineEdit->setText(iv);
        setMessage(QString::fromStdWString(L"[i] Đã tải vào vector khởi tạo !"));
    }
}

//Lưu khóa bí mật
void MainWindow::saveKey()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        QString::fromStdWString(L"Lưu khóa bí mật"),
        QString(), "Key files (*.key);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        QString key = keyLineEdit->text();
        std::string data;
        hexToData(key, data);
        std::string file_name = fileName.toStdString();
        StringSource s(data, true, new FileSink(file_name.c_str()));
        setMessage(QString::fromStdWString(L"[i] Đã lưu khóa bí mật !"));
    }
}

//Lưu vector khởi tạo
void MainWindow::saveIV()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        QString::fromStdWString(L"Lưu vector khởi tạo"),
        QString(), "IV files (*.iv);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        QString iv = ivLineEdit->text();
        std::string data;
        hexToData(iv, data);
        std::string file_name = fileName.toStdString();
        StringSource s(data, true, new FileSink(file_name.c_str()));
        setMessage(QString::fromStdWString(L"[i] Đã lưu vector khởi tạo !"));
    }
}

//Thực hiện mã hóa
void MainWindow::encrypt()
{
    try
    {
        clearCipherText();
        std::string plain = plainTextEdit->toPlainText().toStdString();
        QString keyHex = keyLineEdit->text().trimmed();
        QString ivHex = ivLineEdit->text().trimmed();
        if (checkKeyAndIV(keyHex, ivHex) == false)
        {
            return;
        }
        if (plain.empty())
        {
            setMessage(QString::fromStdWString(L"ERROR: Chưa có nội dung bản rõ"));
            return;
        }

        int size = mKeySizeList[keySizeComboBox->currentIndex()];
        byte* key = new byte[size];
        byte* iv = new byte[AES::BLOCKSIZE];
        hexToData(keyHex, key, size);
        hexToData(ivHex, iv, AES::BLOCKSIZE);

        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key, size, iv);
        std::string cipher;
        StringSource s(plain, true,
            new StreamTransformationFilter(enc,
                new StringSink(cipher)
            )
        );

        QString cipherHex = dataToHex(cipher);
        cipherTextEdit->setPlainText(cipherHex);
        setMessage(QString::fromStdWString(L"[i] Đã mã hóa xong !"));

    }
    catch (const Exception& e)
    {
        setMessage(QString("ERROR: %1").arg(e.what()));
    }
}


//Thực hiện giải mã
void MainWindow::decrypt()
{
    try
    {
        clearRecoveredText();
        std::string cipher;
        hexToData(cipherTextEdit->toPlainText(), cipher);
        QString keyHex = keyLineEdit->text().trimmed();
        QString ivHex = ivLineEdit->text().trimmed();
        if (checkKeyAndIV(keyHex, ivHex) == false)
        {
            return;
        }
        if (cipher.empty())
        {
            setMessage(QString::fromStdWString(L"ERROR: Chưa có nội dung bản mã"));
            return;
        }

        int size = mKeySizeList[keySizeComboBox->currentIndex()];
        byte* key = new byte[size];
        byte* iv = new byte[AES::BLOCKSIZE];
        hexToData(keyHex, key, size);
        hexToData(ivHex, iv, AES::BLOCKSIZE);

        CBC_Mode< AES >::Decryption dec;
        dec.SetKeyWithIV(key, size, iv);
        std::string recovered;
        StringSource s(cipher, true,
            new StreamTransformationFilter(dec,
                new StringSink(recovered)
            )
        );
        recoveredTextEdit->setPlainText(QString::fromStdString(recovered));
        setMessage(QString::fromStdWString(L"[i] Đã giải mã xong !"));
    }
    catch (const Exception& e)
    {
        setMessage(QString("ERROR: %1").arg(e.what()));
        recoveredTextEdit->setPlainText(QString("ERROR: %1").arg(e.what()));
    }
}

//Chuyển hex về dạng dữ liệu byte
void MainWindow::hexToData(const QString& hex, std::string& data)
{
    data.clear();
    std::string hexStd = hex.toStdString();
    StringSource s2(hexStd, true,
        new HexDecoder(
            new StringSink(data)
        )
    );
}

//Chuyển hex về dạng dữ liệu byte
void MainWindow::hexToData(const QString& hex, byte* data, int size)
{
    std::string hexStd = hex.toStdString();
    StringSource s2(hexStd, true,
        new HexDecoder(
            new ArraySink(data, size)
        )
    );
}

//chuyển dữ liệu từ mảng byte thành hex để hiển thị
QString MainWindow::dataToHex(const byte* data, int size)
{
    std::string hex;
    StringSource s(data, size, true,
        new HexEncoder(
            new StringSink(hex)
        )
    );
    return QString::fromStdString(hex);
}

//chuyển dữ liệu từ string thành hex để hiển thị
QString MainWindow::dataToHex(const std::string& data)
{
    std::string hex;
    StringSource s(data, true,
        new HexEncoder(
            new StringSink(hex)
        )
    );
    return QString::fromStdString(hex);
}

//Kiểm tra sự hợp lệ của khóa và vector khởi tạo
//Độ dài khóa phải là 128, 192 hoặc 256 bit. TƯơng đương
//hex của khóa phải có độ dài 32, 48, hoặc 64 kí tự
bool MainWindow::checkKeyAndIV(const QString& keyHex, const QString& ivHex)
{
    if (keyHex.length() != 32 &&
        keyHex.length() != 48 &&
        keyHex.length() != 64)
    {
        setMessage(QString::fromStdWString(L"ERROR: Độ dài khóa không hợp lệ"));
        return false;
    }
    if (checkHexa(keyHex) == false)
    {
        setMessage(QString::fromStdWString(L"ERROR: Khóa bí mật dạng hex không hợp lệ"));
    }
    if (ivHex.length() != 32)
    {
        setMessage(QString::fromStdWString(L"ERROR: Độ dài vector khởi tạo không hợp lệ"));
        return false;
    }
    if (checkHexa(ivHex) == false)
    {
        setMessage(QString::fromStdWString(L"ERROR: Vector khởi tạo dạng hex không hợp lệ"));
    }
    return true;
}

//Kiểm tra sự hợp lệ của dữ liệu hexa
bool MainWindow::checkHexa(const QString data)
{
    QString dataUpper = data.toUpper();
    const QString hexa = "0123456789ABCDEF";
    for (int i = 0; i < dataUpper.length(); ++i)
    {
        if (hexa.contains(dataUpper[i]) == false)
        {
            return false;
        }
    }
    return true;
}

void MainWindow::detectKeySize()
{
    QString keyHex = keyLineEdit->text();
    if (keyHex.length() == 32)
    {
        keySizeComboBox->setCurrentIndex(0);
    }
    else if (keyHex.length() == 48)
    {
        keySizeComboBox->setCurrentIndex(1);
    }
    else if (keyHex.length() == 64)
    {
        keySizeComboBox->setCurrentIndex(2);
    }
    else
    {
        setMessage(QString::fromStdWString(L"ERROR: Lỗi chiều dài khóa bí mật"));
    }
}

void MainWindow::loadPlainText()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        QString::fromStdWString(L"Chọn bản rõ"),
        QString(), "Text files (*.txt);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        QFile file(fileName);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            QTextStream stream(&file);
            stream.setCodec("UTF-8");
            QString all = stream.readAll();
            plainTextEdit->setPlainText(all);
            file.close();
            setMessage(QString::fromStdWString(L"[i] Đã tải bản rõ xong !"));
        }
        else
        {
            setMessage(QString("ERROR: Load %1").arg(fileName));
        }
    }
}

void MainWindow::loadCipherText()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        QString::fromStdWString(L"Chọn bản rõ"),
        QString(), "Text files (*.txt);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        std::string data;
        std::string file_name = fileName.toStdString();
        FileSource file(file_name.c_str(), true, new StringSink(data));
        QString cipherHex = dataToHex(data);
        cipherTextEdit->setPlainText(cipherHex);
        setMessage(QString::fromStdWString(L"[i] Đã tải bản mã xong !"));
    }
}

void MainWindow::savePlainText()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        QString::fromStdWString(L"Lưu bản rõ"),
        QString(), "Text files (*.txt);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QTextStream stream(&file);
            stream.setCodec("UTF-8");
            QString all = plainTextEdit->toPlainText();
            stream << all;
            file.close();
            setMessage(QString::fromStdWString(L"[i] Đã lưu bản rõ xong !"));
        }
        else
        {
            setMessage(QString("ERROR: Save %1").arg(fileName));
        }
    }
}

void MainWindow::saveCipherText()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        QString::fromStdWString(L"Lưu bản mã"),
        QString(), "Text files (*.txt);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        QString cipherHex = cipherTextEdit->toPlainText();
        std::string data;
        hexToData(cipherHex, data);
        std::string file_name = fileName.toStdString();
        StringSource s(data, true, new FileSink(file_name.c_str()));
        setMessage(QString::fromStdWString(L"[i] Đã lưu bản mã xong !"));
    }
}

void MainWindow::saveRecoveredText()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        QString::fromStdWString(L"Lưu bản giải mã"),
        QString(), "Text files (*.txt);;All files (*.*)");
    if (!fileName.isEmpty())
    {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QTextStream stream(&file);
            stream.setCodec("UTF-8");
            QString all = plainTextEdit->toPlainText();
            stream << all;
            file.close();
            setMessage(QString::fromStdWString(L"[i] Đã lưu bản giải mã xong !"));
        }
        else
        {
            setMessage(QString("ERROR: Save %1").arg(fileName));
        }
    }
}

void MainWindow::clearPlainText()
{
    plainTextEdit->clear();
}

void MainWindow::clearCipherText()
{
    cipherTextEdit->clear();
}

void MainWindow::clearRecoveredText()
{
    recoveredTextEdit->clear();
}

//Hiển thị thông báo sau 5 giây
void MainWindow::setMessage(const QString& message)
{
    mMessageLabel->setText(message);
    QTimer::singleShot(5000, [=] { mMessageLabel->clear(); });
    QApplication::beep();
}
