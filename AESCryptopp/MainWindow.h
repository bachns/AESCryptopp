#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtWidgets/QMainWindow>
#include "ui_MainWindow.h"

#include "cryptopp/config_int.h"
using CryptoPP::byte;

#include "cryptopp/osrng.h"
using CryptoPP::RandomNumberGenerator;

class MainWindow : public QMainWindow, Ui::MainWindowClass
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = Q_NULLPTR);

private slots:
    void generateKey();
    void generateIV();
    void loadKey();
    void loadIV();
    void saveKey();
    void saveIV();
    void encrypt();
    void decrypt();

    void loadPlainText();
    void loadCipherText();
    void savePlainText();
    void saveCipherText();
    void saveRecoveredText();
    void clearPlainText();
    void clearCipherText();
    void clearRecoveredText();

private:
    QLabel* mMessageLabel = nullptr;
    RandomNumberGenerator* mRNG = nullptr;
    int* mKeySizeList = nullptr;

    //Chuyển dữ liệu về dạng hex
    QString dataToHex(const byte* data, int size);
    QString dataToHex(const std::string& data);
    void hexToData(const QString& hex, std::string& data);
    void hexToData(const QString& hex, byte* data, int size);
    void setMessage(const QString& message);
    bool checkKeyAndIV(const QString& keyHex, const QString& ivHex);
    bool checkHexa(const QString data);
    void detectKeySize();
};

#endif