#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Process.h"
#include <sstream>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    currentProcess.dwSize = {0};
    currentModule.dwSize = {0};
    
    // Timer for updating mod and proc info:
    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(Update()));
    this->timer->start(2000);
}

MainWindow::~MainWindow()
{
    disconnect(timer, SIGNAL(timeout()), this, SLOT(Update()));
    delete ui;
}

// Function on timer:
void MainWindow::Update(){
    UpdateProcInfo();
    UpdateModInfo();
    return;
}

void MainWindow::ResetWindowTitle(){
    this->setWindowTitle("ZEF - Z0F Exploitation Framework");
}

void MainWindow::Log(QString str){
    ui->txt_Debug->appendPlainText(str);
}

void MainWindow::on_btn_Clear_clicked()
{
    ui->txt_Debug->setPlainText("");
}

// Update proc tab (main timer):
void MainWindow::UpdateProcInfo(){
    ui->txt_ProcInfo->clear();

    if(!currentProcess.dwSize){
        ui->lbl_ProcID->setText("Process ID -");
        return;
    }

    ui->lbl_ProcID->setText("Process ID - " + QString::number(currentProcess.th32ProcessID));
    ui->txt_ProcInfo->appendPlainText("Name: " + QString::fromStdWString(currentProcess.szExeFile));
    ui->txt_ProcInfo->appendPlainText("ID: " + QString::number(currentProcess.th32ProcessID));
    ui->txt_ProcInfo->appendPlainText("Parent Process: " + QString::fromStdWString((GetProcEntry(currentProcess.th32ParentProcessID).szExeFile))
                                      + " (" + QString::number(currentProcess.th32ParentProcessID) + ")");
    ui->txt_ProcInfo->appendPlainText("Num of Threads: " + QString::number(currentProcess.cntThreads));
    return;
}

// Update mod tab (main timer):
void MainWindow::UpdateModInfo(){
    ui->txt_ModInfo->clear();

    if(!currentModule.dwSize){
        ui->lbl_ModAddr->setText("Module Address -");
        return;
    }

    QString modAddr = QString("%1").arg((quintptr)currentModule.modBaseAddr, QT_POINTER_SIZE * 2, 16, QChar('0')).toUpper();

    ui->lbl_ModAddr->setText("Module Address - " + modAddr);
    ui->txt_ModInfo->appendPlainText("Name: " + QString::fromWCharArray(currentModule.szModule));
    ui->txt_ModInfo->appendPlainText("Path: " + QString::fromWCharArray(currentModule.szExePath));
    ui->txt_ModInfo->appendPlainText("Process ID: " + QString::number(currentModule.th32ProcessID));
    ui->txt_ModInfo->appendPlainText("Base Address: " + modAddr);
    ui->txt_ModInfo->appendPlainText("Size: " + QString::number(currentModule.modBaseSize));
    return;
}

void MainWindow::on_action_About_triggered()
{
    QMessageBox msg;
    msg.setTextFormat(Qt::TextFormat::MarkdownText);
    msg.setWindowTitle("About");
    msg.setText("## ZEF - Z0F Exploitation Framework\n###\t   Made by Z0F\nFollow me on [Twitter](https://twitter.com/0xZ0F)\n\nCheck out my [GitHub](https://github.com/0xZ0F)");
    msg.exec();
}

// Get Proc by Name:
void MainWindow::on_btn_GetProcID_clicked()
{
    DWORD procID = GetProcID(ui->txt_ProcName->text().toStdWString());

    if(procID == 0xFFFFFFFF){
        Log("Couldn't find proces.");
        currentProcess = {0};
        currentModule = {0};
        ResetWindowTitle();
        return;
    }

    setWindowTitle("ZEF - " + ui->txt_ProcName->text() + " : " + QString::number(procID));
    Log("Found process ID " + QString::number(procID) + " with name " + ui->txt_ProcName->text() + ".");

    currentProcess = GetProcEntry(procID);
    UpdateProcInfo();
}

// Get Proc By ID:
void MainWindow::on_btn_GetProcName_clicked()
{
    QString procName;
    bool isNum;

    //Check if input is a number:
    ui->txt_ProcName->text().toInt(&isNum, 10);
    if(!isNum){goto __invalidID;}

    procName = GetProcName(ui->txt_ProcName->text().toULong());
    if(procName.isEmpty()){
        __invalidID:
        Log("ERROR: Invalid Process ID.");
        ResetWindowTitle();
        return;
    }

    currentProcess = GetProcEntry(ui->txt_ProcName->text().toULong());
    UpdateProcInfo();

    ui->txt_ProcName->setText(procName);
    setWindowTitle("ZEF - " + ui->txt_ProcName->text() + " : " + ui->lbl_ProcID->text());
    Log("Found process \"" + procName + "\" with ID " + QString::number(currentProcess.th32ProcessID) + ".");
}

// Get module address and info (UpdateModInfo):
void MainWindow::on_btn_GetModAddr_clicked()
{
    currentModule = GetModule(currentProcess.th32ProcessID, ui->txt_ModName->text().toStdWString());

    if(!currentModule.dwSize){
        Log("ERROR: Invalid Module Name.");
        currentModule = {0};
        return;
    }

    Log("Found module " + ui->txt_ModName->text() + " at " + QString("%1").arg((quintptr)currentModule.modBaseAddr, QT_POINTER_SIZE * 2, 16, QChar('0')).toUpper() + ".");
    UpdateModInfo();
}

// Read mem starting at addr:
void MainWindow::on_btn_Read_clicked()
{
    byte currByte;
    bool isValid;
    int size;
    ULONGLONG addr;
    HANDLE hProc = NULL;

    // Get size to be read:
    size = ui->txt_Size->text().toInt(&isValid, 10);
    // Input Validation:
    if(!isValid || ui->txt_Size->text().toInt() < 1){
        Log("Invalid Size.");
        goto __RET;
    }else if(!currentModule.dwSize){
        Log("Module needed before reading or writing memory.");
        goto __RET;
    }else if(size > 2048){
        Log("Read amount too large. Max of 2048 bytes.");
        goto __RET;
    }
    // Set Addr Var:
    addr = ui->txt_Address->text().toULongLong(&isValid, 16);
    if(!isValid){
        Log("Invalid Address.");
        goto __RET;
    }


    ui->txt_Output->clear();
    ui->txt_Output->insertPlainText("Reading " + QString::number(size) + " bytes from " + QString::number(addr, 16).toUpper()
                                    + " in module " + QString::fromStdWString(currentModule.szModule) + ":\n");

    // Read from addr, size number of bytes:
    hProc = OpenProcess(PROCESS_VM_READ, false, currentProcess.th32ProcessID);
    for(int x = 0; x < size; x++){
        ReadProcessMemory(hProc, (LPCVOID)(addr + x), &currByte, 1, NULL);
        ui->txt_Output->insertPlainText(QString("%1 ").arg(currByte, 2, 16, QChar('0')).toUpper());
    }
    Log("Read " + QString::number(size) + " bytes at " + QString::number(addr, 16).toUpper() + ".");

    __RET:
    CloseHandle(hProc);
    return;
}

// Write bytes to addr:
void MainWindow::on_btn_Write_clicked()
{
    DWORD oldProtect;
    size_t numWritten = 0;
    int inputOffset = 0;
    int addrOffset = 0;
    ULONGLONG addr = ui->txt_Address->text().toULongLong(NULL, 16);
    unsigned char* data = new unsigned char;
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, currentProcess.th32ProcessID);

    if(!ProcAndMod(currentProcess, currentModule)){
        Log("Invlaid module or process.");
        goto __RET;
    }

    if((ui->txt_Write->text().length() % 2 != 0) || (ui->txt_Write->text().isEmpty())){
        Log("Invalid number of bytes to write. Must be a multiple of 2.");
        goto __RET;
    }

    // Write:
    VirtualProtectEx(hProc, (void*)addr, ui->txt_Write->text().length()/2, PAGE_EXECUTE_READWRITE, &oldProtect);
    while(addrOffset < ui->txt_Write->text().length()/2){
        *data = ui->txt_Write->text().mid(inputOffset, 2).toUShort(NULL, 16);
        WriteProcessMemory(hProc, (void*)(addr+addrOffset), data, 1, &numWritten);
        inputOffset+=2;
        addrOffset++;
    }
    VirtualProtectEx(hProc, (void*)addr, ui->txt_Write->text().length()/2, oldProtect, &oldProtect);

    if(!numWritten){
        Log("Internal Error: write failed.");
        goto __RET;
    }
    Log("Wrote " + QString::number(ui->txt_Write->text().length()/2) + " bytes at " + QString("%1 ").arg(addr, 2, 16, QChar('0')).toUpper() + ".");

    __RET:
    CloseHandle(hProc);
    return;
}

// List all modules for the process (MOD + BASE_ADDR):
void MainWindow::on_btn_GetAllMods_clicked()
{
    if(!currentProcess.dwSize){
        Log("No process to find modules for.");
        return;
    }

    Log("--- Listing all modules for " + QString::fromStdWString(currentProcess.szExeFile) + " ---");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, currentProcess.th32ProcessID);

    // Loop over hSnapshot and log mods:
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 curr;
        curr.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &curr)) {
            do {
                Log(QString::fromStdWString(curr.szModule) + " - " + QString("%1").arg((quintptr)curr.modBaseAddr, QT_POINTER_SIZE * 2, 16, QChar('0')).toUpper());
            } while (Module32Next(hSnapshot, &curr));
        }
        CloseHandle(hSnapshot);
    }else{
        Log("Internal Error: Couldn't create snapshot.");
    }

    CloseHandle(hSnapshot);
    Log("--- End of modules for " + QString::fromStdWString(currentProcess.szExeFile) + " ---");
}


