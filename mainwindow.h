#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <Windows.h>
#include <TlHelp32.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void ResetWindowTitle();
    void Log(QString str);
    void UpdateProcInfo();
    void UpdateModInfo();

private slots:
    void on_btn_GetProcID_clicked();

    void on_btn_GetProcName_clicked();

    void on_btn_GetModAddr_clicked();

    void Update();

    void on_btn_Read_clicked();

    void on_btn_GetAllMods_clicked();

    void on_btn_Write_clicked();

    void on_btn_Clear_clicked();

    void on_action_About_triggered();

private:
    Ui::MainWindow *ui;
    QTimer *timer;
    PROCESSENTRY32 currentProcess;
    MODULEENTRY32 currentModule;
};
#endif // MAINWINDOW_H
