#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QMainWindow>
#include <D:\Qt\Tools\OpenSSLv3\Win_x64\include\openssl\evp.h>
#include <D:\Qt\Tools\OpenSSLv3\Win_x64\include\openssl\types.h>
class Cridential {
public:
    QString hostname;
    QString login;
    QString password;

};
QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool readJSON(QByteArray key_hex);
    QByteArray showPinDialog();
    bool Pflag;
    bool Lflag;

public slots:
    int decryptFile(const QByteArray &encryptedBytes, QByteArray &decryptedBytes, const QByteArray &key_hex);
    void filterAccounts(const QString &fragment);

private slots:
    void on_edtPin_returnPressed();
    void decryptLogin(int id);
    void decryptPassword(int id);

private:
    Ui::MainWindow *ui;
    QJsonArray m_jsonarray; // структура данных содержащая учетные записи
    bool m_isStartUp = true;
    int m_current_id=-1;
};
#endif // MAINWINDOW_H
