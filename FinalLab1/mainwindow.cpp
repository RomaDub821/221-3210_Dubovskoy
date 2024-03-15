#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "cridentialwidget.h"
#include <QFile>
#include <QJsonDocument>
#include <QMainWindow>
#include <QApplication>
#include <QListWidget>
#include <QDataStream>
#include <QBuffer>
#include <QCryptographicHash>
#include <QClipboard>
#include <D:\Qt\Tools\OpenSSLv3\Win_x64\include\openssl\evp.h>
#include <D:\Qt\Tools\OpenSSLv3\Win_x64\include\openssl\types.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->lineEdit, &QLineEdit::textChanged, this, &MainWindow::filterAccounts);
    for(int i = 0; i < m_jsonarray.size(); i++)
    {
        QJsonObject obj = m_jsonarray[i].toObject();
        QString site = obj["site"].toString();
        QListWidgetItem * newItem = new QListWidgetItem();
        CridentialWidget * itemWidget = new CridentialWidget(site, /*login, password,*/ i);
        newItem->setSizeHint(itemWidget->sizeHint());
        ui->listWidget->addItem(newItem);
        ui->listWidget->setItemWidget(newItem, itemWidget);
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

/*Функция считывания записи из файла JSON в структуру данных QList*/
bool MainWindow::readJSON(QByteArray key_hex)
{
    if (key_hex != "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4") {
        return false;
    }
    QFile jsonFile("cridentialsencrypted.txt");
    jsonFile.open(QFile::ReadOnly);
    if (!jsonFile.isOpen())
        return false;
    QByteArray hexEncryptedBytes = jsonFile.readAll();
    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    QByteArray decryptedBytes;
    decryptFile(encryptedBytes, decryptedBytes, key_hex);
    qDebug() << "*** DecryptedBytes" << decryptedBytes;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes);
    qDebug() << "***jsonDoc = " << jsonDoc;
    QJsonObject rootObject = jsonDoc.object();
    m_jsonarray = rootObject["cridentials"].toArray();
    jsonFile.close();
    qDebug() << "*** m_jsonarray:";
    for(int i = 0; i < m_jsonarray.size(); i++) {
        qDebug() << m_jsonarray[i].toObject();
    }
    return true;
}

// Реализация слота
void MainWindow::filterAccounts(const QString &fragment) {
    ui->listWidget->clear();
    for (int i = 0; i < m_jsonarray.size(); i++) {
        QString site = m_jsonarray[i].toObject()["site"].toString().toLower();
        if (site.contains(fragment.toLower())) {
            QListWidgetItem *newItem = new QListWidgetItem();
            CridentialWidget *itemWidget = new CridentialWidget(site, /*login, password,*/ i);
            QObject::connect(itemWidget, &CridentialWidget::decryptLogin, this, &MainWindow::decryptLogin);
            QObject::connect(itemWidget, &CridentialWidget::decryptPassword, this, &MainWindow::decryptPassword);
            newItem->setSizeHint(itemWidget->sizeHint());
            ui->listWidget->addItem(newItem);
            ui->listWidget->setItemWidget(newItem, itemWidget);
        }
    }
}

int MainWindow::decryptFile(const QByteArray & encryptedBytes, QByteArray & decryptedBytes, const QByteArray &key_hex)
{
    // iv= 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    // password = 1234
    // key= SHA256(password) = 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4
    //QByteArray key_hex("03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4");
    QByteArray key_ba = QByteArray::fromHex(key_hex);
    unsigned char key[32] = {0};
    memcpy(key, key_ba.data(), 32);
    QByteArray iv_hex("000102030405060708090a0b0c0d0e0f");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    unsigned char iv[16] = {0};
    memcpy(iv, iv_ba.data(), 16);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL))
    {
        qDebug() << "*** EVP_DecryptInit_ex2() ERROR";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    decryptedBytes.clear();

#define BUF_LEN 256
    unsigned char encrypted_buf[BUF_LEN] = {0}, decrypted_buf[BUF_LEN] = {0};
    int encr_len, decr_len;
    QDataStream encrypted_stream(encryptedBytes);
    QBuffer decrypted_buffer(&decryptedBytes);
    decryptedBytes.clear();
    decrypted_buffer.open(QBuffer::WriteOnly);
    encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    while(encr_len>0)
    {
        //собственно расшифрование очередной порции
        if (!EVP_DecryptUpdate(ctx, decrypted_buf, &decr_len, encrypted_buf, encr_len))
        {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        qDebug() << "*** DECRYPT: " << reinterpret_cast<char*>(decrypted_buf);
        //накопление расшифрованного результата
        decrypted_buffer.write(reinterpret_cast<char*>(decrypted_buf), decr_len);
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    }
    qDebug() << "*** before EVP_DecryptFinal_ex" <<decrypted_buffer.data();
    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buf, &tmplen))
    {
        qDebug() << "*** EVP_DecryptFinal_ex() ERROR";
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    decrypted_buffer.write(reinterpret_cast<char*>(decrypted_buf), tmplen);
    decrypted_buffer.close();
    EVP_CIPHER_CTX_free(ctx);
    qDebug() << "*** after EVP_DecryptFinal_ex" << decr_len << reinterpret_cast<char*>(decrypted_buf);
    return 0;
}

void MainWindow::on_edtPin_returnPressed()
{
    //1. Получить ключ из пин-кода
    QByteArray hash = QCryptographicHash::hash(
        ui->edtPin->text().toUtf8(),
        QCryptographicHash::Sha256);
    qDebug() << "***Sha256= " << hash.toHex();
    if (m_isStartUp) {
        //3. Расшифровать файл и проверить верность пин-кода
        if (readJSON(hash.toHex())) {
            ui->stackedWidget->setCurrentIndex(0);
            filterAccounts("");
            m_isStartUp = false;
        }
        else {
            ui->lblLogin->setText("Неверный пин-код");
            ui->lblLogin->setStyleSheet("color:red;");
        }
    }
    else {
        QByteArray encrypted_creds = QByteArray::fromHex(m_jsonarray[m_current_id].toObject()["logpass"].toString().toUtf8());
        QByteArray decrypted_creds;
        decryptFile(encrypted_creds, decrypted_creds, hash.toHex());
        QString login;
        QJsonDocument jsonDoc = QJsonDocument::fromJson(decrypted_creds);
        if (!jsonDoc.isNull() && jsonDoc.isObject()) {
            QJsonObject jsonObject = jsonDoc.object();
            if (jsonObject.contains("login") && jsonObject["login"].isString()) {
                login = jsonObject["login"].toString();
            }
        }
        QString password;
        if (!jsonDoc.isNull() && jsonDoc.isObject()) {
            QJsonObject jsonObject = jsonDoc.object();
            if (jsonObject.contains("password") && jsonObject["password"].isString()) {
                password = jsonObject["password"].toString();
            }
        }
        if (Lflag) {
            qDebug() << login;
            QGuiApplication::clipboard()->setText(login);
        } else if (Pflag) {
            QGuiApplication::clipboard()->setText(password);
        }
        qDebug() << "**1** decrypted_creds" << decrypted_creds;
        QString decryptedString = QString::fromUtf8(decrypted_creds);
        qDebug() << "**2** decrypted_creds" << decryptedString;
        ui->stackedWidget->setCurrentIndex(0);
    }
    //2 Удалить ключ и пин-код
    ui->edtPin->setText(QString().fill('*', ui->edtPin->text().size()));
    ui->edtPin->clear();
    hash.setRawData(
        const_cast<char*>(QByteArray().fill('*', 32).data()), 32);
    hash.clear();
}

void MainWindow::decryptLogin(int id)
{
        qDebug()<< "*** slot decryptLogin()";
        qDebug()<< m_jsonarray[id].toObject()["logpass"].toString();
        m_current_id=id;
        ui->stackedWidget->setCurrentIndex(1);
        Lflag=true;
        Pflag=false;
}

void MainWindow::decryptPassword(int id)
{
        m_current_id=id;
        ui->stackedWidget->setCurrentIndex(1);
        Pflag=true;
        Lflag=false;
}

QByteArray MainWindow::showPinDialog()
{
        ui->stackedWidget->setCurrentIndex(1);
        return QByteArray();
}
