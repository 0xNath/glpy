#!python
from glpi import arguments, setupArgumentsParsing, GLPI as GLPIServer
from typing import List
import os
import json

import sys
from PySide6 import QtCore, QtWidgets, QtGui


class mainWindow(QtWidgets.QWidget):

    def __setupWidgets(self):
        self.lineEdit_text = QtWidgets.QLineEdit(self)
        self.lineEdit_text.setPlaceholderText("Text to search")
        self.layout().addWidget(self.lineEdit_text)

        self.groupBox_preSearchOptions = QtWidgets.QGroupBox(self)
        self.groupBox_preSearchOptions.setTitle(
            "Options to filter ticker before deep searching"
        )
        self.groupBox_preSearchOptions.setLayout(QtWidgets.QGridLayout())
        self.layout().addWidget(self.groupBox_preSearchOptions)

        self.groupBox_searchOptions = QtWidgets.QGroupBox(self)
        self.groupBox_searchOptions.setTitle("search features")
        self.groupBox_searchOptions.setLayout(QtWidgets.QHBoxLayout())

        self.searchInReplies = QtWidgets.QCheckBox("Replies")
        self.searchInReplies.setChecked(True)
        self.searchInDOCX = QtWidgets.QCheckBox("DOCX")
        self.searchInXLSX = QtWidgets.QCheckBox("XLSX")
        self.searchInPDF = QtWidgets.QCheckBox("PDF")
        self.searchInImages = QtWidgets.QCheckBox("Images")
        self.searchInUnknownFiles = QtWidgets.QCheckBox("Unknown Files")
        self.followTicketLinks = QtWidgets.QCheckBox("Follow ticket links")
        self.followTicketLinks.setChecked(True)

        self.groupBox_searchOptions.layout().addWidget(self.searchInReplies)
        self.groupBox_searchOptions.layout().addWidget(self.searchInDOCX)
        self.groupBox_searchOptions.layout().addWidget(self.searchInXLSX)
        self.groupBox_searchOptions.layout().addWidget(self.searchInPDF)
        self.groupBox_searchOptions.layout().addWidget(self.searchInImages)
        self.groupBox_searchOptions.layout().addWidget(self.searchInUnknownFiles)
        self.groupBox_searchOptions.layout().addWidget(self.followTicketLinks)

        self.layout().addWidget(self.groupBox_searchOptions)

        self.tableWidget_results = QtWidgets.QTableWidget()
        self.tableWidget_results.setColumnCount(3)
        self.tableWidget_results.verticalHeader().hide()

        self.tableWidget_results.setHorizontalHeaderItem(
            0, QtWidgets.QTableWidgetItem("Ticket ID")
        )

        self.tableWidget_results.setHorizontalHeaderItem(
            1, QtWidgets.QTableWidgetItem("search progress")
        )

        self.tableWidget_results.setHorizontalHeaderItem(
            2, QtWidgets.QTableWidgetItem("result")
        )

        self.tableWidget_results.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

        self.tableWidget_results.horizontalHeader().setStretchLastSection(True)

        self.tableWidget_results.sortByColumn(1, QtCore.Qt.SortOrder.AscendingOrder)
        self.layout().addWidget(self.tableWidget_results)

        self.label_errorMessage = QtWidgets.QLabel("")
        self.label_errorMessage.setStyleSheet("QLabel { color : red; }")
        self.label_errorMessage.setWordWrap(True)
        self.label_errorMessage.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.label_errorMessage.hide()
        self.layout().addWidget(self.label_errorMessage)

        self.progressBar_search = QtWidgets.QProgressBar(self)
        self.layout().addWidget(self.progressBar_search)
        self.progressBar_search.hide()

        self.pushButton_search = QtWidgets.QPushButton("Search")
        self.layout().addWidget(self.pushButton_search)
        self.pushButton_search.clicked.connect(self.search)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("GLPY - Search")

        self.setMinimumSize(750, 800)
        self.ticketSearchOptions: dict = {}

        self.server = GLPIServer
        self.availableCores = os.sched_getaffinity(0)

        self.searchProcessPools: List[QtCore.QProcess] = []
        self.processFinished = 0
        self.tickets: List[dict] = []
        self.ticketsPools: List[str] = [""] * len(self.availableCores)
        self.ticketsSearched = 0

        self.ticketIDLength = 1

        self.searchOptionRowCount = 0

        self.setLayout(QtWidgets.QVBoxLayout())

        self.__setupWidgets()

    def addNewSearchOptionLine(self):
        rowCount = self.groupBox_preSearchOptions.layout().rowCount() - 1

        pushButton_logic = QtWidgets.QComboBox()
        pushButton_logic.addItem("AND")
        pushButton_logic.addItem("OR")
        pushButton_logic.addItem("AND NOT")
        pushButton_logic.addItem("OR NOT")
        pushButton_logic.addItem("🗑")
        self.groupBox_preSearchOptions.layout().addWidget(pushButton_logic, rowCount, 0)

        comboBox_option = QtWidgets.QComboBox()
        comboBox_option.setEditable(True)

        for category in self.ticketSearchOptions.values():
            for optionName in list(category.keys()):
                comboBox_option.addItem(optionName)

        comboBox_option.setInsertPolicy(QtWidgets.QComboBox.InsertPolicy.NoInsert)
        self.groupBox_preSearchOptions.layout().addWidget(comboBox_option, rowCount, 1)

        comboBox_option.currentIndexChanged.connect(
            lambda comboBoxIndexPos, comboBoxID=self.searchOptionRowCount: self.changeSearchOptionComparison(
                comboBoxIndexPos, comboBoxID
            )
        )

        comboBox_option.comboBoxID = self.searchOptionRowCount

        comboBox_comparison = QtWidgets.QComboBox()
        comboBox_comparison.setDisabled(True)
        self.groupBox_preSearchOptions.layout().addWidget(
            comboBox_comparison, rowCount, 2
        )

        comboBox_searchValue = QtWidgets.QComboBox()
        comboBox_searchValue.setDisabled(True)
        self.groupBox_preSearchOptions.layout().addWidget(
            comboBox_searchValue, rowCount, 3
        )

        self.searchOptionRowCount += 1

    def changeSearchOptionComparison(self, comboBoxIndexPos: int, comboBoxID: int):
        layout: QtWidgets.QGridLayout = self.groupBox_preSearchOptions.layout()

        for rowPos in range(0, layout.rowCount()):
            item = layout.itemAtPosition(rowPos, 1)

            if comboBoxID == item.widget().comboBoxID:

                comboBox_option: QtWidgets.QComboBox = layout.itemAtPosition(
                    rowPos, 1
                ).widget()
                comboBox_comparison = layout.itemAtPosition(rowPos, 2).widget()
                comboBox_searchValue = layout.itemAtPosition(rowPos, 3).widget()
                pass

        for category in self.ticketSearchOptions.values():
            for optionName, optionProperties in list(category.items()):
                if optionName == comboBox_option.currentText():
                    comboBox_comparison.setEnabled(True)
                    comboBox_comparison.clear()
                    comboBox_comparison.addItems(
                        optionProperties["available_searchtypes"]
                    )
                    pass

    def setServer(self, server: GLPIServer):
        self.server = server
        self.ticketSearchOptions = self.server.searchOptions(itemType="Ticket")
        self.addNewSearchOptionLine()

    def handle_stdout(self, pos: int):
        data = self.searchProcessPools[pos].readAllStandardOutput()
        stdout = bytes(data).decode("utf8")
        try:
            object = json.loads(stdout)
        except Exception as e:
            print(e, stdout)
            return

        self.ticketsSearched += 1

        self.progressBar_search.setValue(self.ticketsSearched)

        self.tableWidget_results.item(
            self.tableWidget_results.findItems(
                object["Ticket.id"].zfill(self.ticketIDLength),
                QtCore.Qt.MatchFlag.MatchExactly,
            )[0].row(),
            1,
        ).setText(str(object["progress"]))

        self.tableWidget_results.item(
            self.tableWidget_results.findItems(
                object["Ticket.id"].zfill(self.ticketIDLength),
                QtCore.Qt.MatchFlag.MatchExactly,
            )[0].row(),
            2,
        ).setText(object["result"])

    def handle_stderr(self, pos: int):
        data = self.searchProcessPools[pos].readAllStandardError()
        stderr = bytes(data).decode("utf8")
        print(f"process : {pos}\n{stderr}", file=sys.stderr)

    def process_finished(self, pos: int):
        self.processFinished += 1

        if self.processFinished == len(self.searchProcessPools):
            self.lineEdit_text.setDisabled(False)
            self.pushButton_search.setDisabled(False)

            self.searchProcessPools: List[QtCore.QProcess] = []
            self.ticketsPools: List[str] = [""] * len(self.availableCores)

    def search(self):
        self.label_errorMessage.hide()
        self.progressBar_search.show()
        self.pushButton_search.setDisabled(True)
        self.lineEdit_text.setDisabled(True)
        self.tableWidget_results.setSortingEnabled(False)

        searchResults = self.server.search(itemType="Ticket", range="0-9999999999")

        if "data" not in searchResults:
            self.label_errorMessage.setText("No tickets has been found.")
            self.label_errorMessage.show()
            self.pushButton_search.setEnabled(True)
            return

        self.tickets = list(searchResults["data"].keys())

        self.ticketIDLength = 1
        for ticket in self.tickets:
            if len(ticket) > self.ticketIDLength:
                self.ticketIDLength = len(ticket)

        self.tableWidget_results.clearContents()
        self.tableWidget_results.setRowCount(len(self.tickets))
        self.progressBar_search.setRange(0, len(self.tickets))
        self.progressBar_search.setValue(0)
        self.processFinished = 0
        self.ticketsSearched = 0

        for ticketPosition in range(0, len(self.tickets)):
            self.ticketsPools[ticketPosition % len(self.availableCores)] += (
                self.tickets[ticketPosition] + ","
            )

            self.tableWidget_results.setItem(
                ticketPosition,
                0,
                QtWidgets.QTableWidgetItem(
                    str(self.tickets[ticketPosition]).zfill(self.ticketIDLength)
                ),
            )

            self.tableWidget_results.item(ticketPosition, 0).setTextAlignment(
                QtCore.Qt.AlignmentFlag.AlignHCenter
            )

            self.tableWidget_results.setItem(
                ticketPosition,
                1,
                QtWidgets.QTableWidgetItem("Search not started"),
            )

            self.tableWidget_results.item(ticketPosition, 1).setTextAlignment(
                QtCore.Qt.AlignmentFlag.AlignHCenter
            )

            self.tableWidget_results.setItem(
                ticketPosition,
                2,
                QtWidgets.QTableWidgetItem(""),
            )

        for ticketsPool in range(0, len(self.ticketsPools)):
            self.ticketsPools[ticketsPool] = self.ticketsPools[ticketsPool][
                0 : len(self.ticketsPools[ticketsPool]) - 1
            ]

            if self.ticketsPools[ticketsPool]:
                self.searchProcessPools.append(QtCore.QProcess(self))
                self.searchProcessPools[ticketsPool].readyReadStandardOutput.connect(
                    lambda pos=ticketsPool: self.handle_stdout(pos)
                )
                self.searchProcessPools[ticketsPool].readyReadStandardError.connect(
                    lambda pos=ticketsPool: self.handle_stderr(pos)
                )
                self.searchProcessPools[ticketsPool].finished.connect(
                    lambda pos=ticketsPool: self.process_finished(pos)
                )

                args = [
                    "glpi.py",
                    "--url",
                    self.server.url,
                    "--applicationToken",
                    self.server._getApplicationToken(),
                    "--sessionToken",
                    self.server._getSessionToken(),
                    "--ticketNumbers",
                    self.ticketsPools[ticketsPool],
                    "--textToSearch",
                    self.lineEdit_text.text(),
                ]

                if self.searchInDOCX.isChecked():
                    args.append("--searchInDOCX")

                if self.searchInXLSX.isChecked():
                    args.append("--searchInXLSX")

                if self.searchInPDF.isChecked():
                    args.append("--searchInPDF")

                if self.searchInUnknownFiles.isChecked():
                    args.append("--searchInUnknownFiles")

                if self.searchInImages.isChecked():
                    args.append("--searchInImages")

                if self.searchInImages.isChecked():
                    args.append("--searchInImages")

                if self.followTicketLinks.isChecked():
                    args.append("--followTicketLinks")

                if self.searchInUnknownFiles.isChecked():
                    args.append("--searchInUnknownFiles")

                self.searchProcessPools[ticketsPool].start("python", args)

        self.tableWidget_results.setSortingEnabled(True)


class authWindow(QtWidgets.QWidget):
    def __init__(self, args: arguments, mainWidget: mainWindow):
        super().__init__()

        self.setWindowTitle("GLPY - Auth")

        self.setMinimumSize(500, 400)

        self.setLayout(QtWidgets.QVBoxLayout())

        self.__setupWidgets()

        self.textEdit_url.setText(args.url)
        self.textEdit_applicationToken.setText(args.applicationToken)
        self.textEdit_userToken.setText(args.userToken)
        self.textEdit_username.setText(args.username)
        self.textEdit_password.setText(args.password)

        self.show()

    def __setupWidgets(self):
        self.textEdit_url = QtWidgets.QLineEdit(self)
        self.textEdit_url.setPlaceholderText("URL of the GLPI server web interface")
        self.layout().addWidget(self.textEdit_url)

        self.textEdit_applicationToken = QtWidgets.QLineEdit(self)
        self.textEdit_applicationToken.setPlaceholderText("Application token")
        self.layout().addWidget(self.textEdit_applicationToken)

        self.widget_tokens = QtWidgets.QWidget(self)
        self.widget_tokens.setLayout(QtWidgets.QVBoxLayout())

        self.textEdit_userToken = QtWidgets.QLineEdit(self.widget_tokens)
        self.textEdit_userToken.setPlaceholderText("User token")
        self.textEdit_userToken.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.widget_tokens.layout().addWidget(self.textEdit_userToken)
        self.layout().addWidget(self.widget_tokens)

        self.widget_credentials = QtWidgets.QWidget(self)
        self.widget_credentials.setLayout(QtWidgets.QVBoxLayout())

        self.textEdit_username = QtWidgets.QLineEdit(self.widget_credentials)
        self.textEdit_username.setPlaceholderText("Username")
        self.textEdit_password = QtWidgets.QLineEdit(self.widget_credentials)
        self.textEdit_password.setPlaceholderText("Password")
        self.textEdit_password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.widget_credentials.layout().addWidget(self.textEdit_username)
        self.widget_credentials.layout().addWidget(self.textEdit_password)
        self.layout().addWidget(self.widget_credentials)

        self.label_errorMessage = QtWidgets.QLabel("")
        self.label_errorMessage.setStyleSheet("QLabel { color : red; }")
        self.label_errorMessage.setWordWrap(True)
        self.label_errorMessage.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.label_errorMessage.hide()
        self.layout().addWidget(self.label_errorMessage)

        self.widget_controls = QtWidgets.QWidget(self)
        self.widget_controls.setLayout(QtWidgets.QHBoxLayout(self.widget_controls))

        self.pushButton_authenticate = QtWidgets.QPushButton(
            "Connect", self.widget_controls
        )
        self.pushButton_authenticate.clicked.connect(self.authenticate)

        self.pushButton_cancel = QtWidgets.QPushButton("Cancel", self.widget_controls)
        self.pushButton_cancel.clicked.connect(self.exit)

        self.widget_controls.layout().addWidget(self.pushButton_authenticate)
        self.widget_controls.layout().addWidget(self.pushButton_cancel)
        self.layout().addWidget(self.widget_controls)

    def authenticate(self):
        try:
            server = GLPIServer(
                url=self.textEdit_url.text(),
                applicationToken=self.textEdit_applicationToken.text(),
                userToken=self.textEdit_userToken.text(),
                username=self.textEdit_username.text(),
                password=self.textEdit_password.text(),
            )
        except Exception as e:
            self.label_errorMessage.setHidden(False)
            self.label_errorMessage.setText(str(e))
            return

        mainWidget.setServer(server)
        mainWidget.show()
        self.hide()

    def exit(self):
        app.exit(0)


if __name__ == "__main__":
    args = setupArgumentsParsing()

    app = QtWidgets.QApplication([])

    mainWidget = mainWindow()
    authWidget = authWindow(args, mainWidget)

    sys.exit(app.exec())
