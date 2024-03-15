#include "cridentialwidget.h"
#include "ui_cridentialwidget.h"

CridentialWidget::CridentialWidget(const QString &site, /*const QString &login, const QString &password,*/ const int id, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::CridentialWidget)
    , m_id(id)
{
    ui->setupUi(this);
    ui->lblSite->setText(site);
}

CridentialWidget::~CridentialWidget()
{
    delete ui;
}

void CridentialWidget::on_LgnBtn_clicked()
{
    qDebug() <<"*** Pressed " <<m_id;
    emit decryptLogin(m_id);
}

void CridentialWidget::on_PassBtn_clicked()
{
   qDebug() <<"*** Pressed " <<m_id;
   emit decryptPassword(m_id);
}

