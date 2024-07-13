#!python
from pprint import pprint
from glpi import arguments, setupArgumentsParsing, GLPI as GLPIServer
from typing import List
import os
from math import floor

import sys
from PySide6 import QtCore, QtWidgets, QtGui


class mainWindow(QtWidgets.QWidget):

    def __setupWidgets(self):
        self.lineEdit_text = QtWidgets.QLineEdit()
        self.lineEdit_text.setPlaceholderText("Text to search")
        self.layout.addWidget(self.lineEdit_text)

        self.label_result = QtWidgets.QLabel()
        self.label_result.setWordWrap(True)
        self.label_result.setStyleSheet("QLabel { color : green; }")
        self.label_result.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.label_result.hide()
        self.layout.addWidget(self.label_result)

        self.spacer = QtWidgets.QSpacerItem(
            0,
            0,
            hData=QtWidgets.QSizePolicy.Policy.Expanding,
            vData=QtWidgets.QSizePolicy.Policy.Expanding,
        )
        self.layout.addItem(self.spacer)

        self.pushButton_search = QtWidgets.QPushButton("Search")
        self.layout.addWidget(self.pushButton_search)
        self.pushButton_search.clicked.connect(self.search)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("GLPY - Search")

        self.setMinimumSize(400, 300)

        self.server = GLPIServer

        self.availableCores = os.sched_getaffinity(0)

        self.searchProcessPools: List[QtCore.QProcess] = []
        self.tickets: List[dict] = []
        self.ticketsPools: List[str] = [""] * len(self.availableCores)

        self.layout = QtWidgets.QVBoxLayout(self)

        self.__setupWidgets()

    def setServer(self, server: GLPIServer):
        self.server = server

    def handle_stdout(self, pos: int):
        data = self.searchProcessPools[pos].readAllStandardOutput()
        stdout = bytes(data).decode("utf8")
        print(stdout)
        # self.label_result.setText(stdout)
        self.label_result.show()

        self.lineEdit_text.setDisabled(False)
        self.pushButton_search.setDisabled(False)

    def handle_stderr(self, pos: int):
        data = self.searchProcessPools[pos].readAllStandardError()
        stderr = bytes(data).decode("utf8")
        print(stderr)

    def process_finished(self, pos: int):
        ...
        # self.searchProcessPools[pos].deleteLater()
        # self.searchProcessPools.pop(pos)

    def search(self):
        self.label_result.hide()
        self.pushButton_search.setDisabled(True)
        self.lineEdit_text.setDisabled(True)

        self.tickets = list(
            self.server.search(itemType="Ticket", range="0-9999999999")["data"].keys()
        )

        for ticketPosition in range(0, len(self.tickets)):
            self.ticketsPools[ticketPosition % len(self.availableCores)] += (
                self.tickets[ticketPosition] + ","
            )

        for ticketsPool in range(0, len(self.ticketsPools)):
            self.ticketsPools[ticketsPool] = self.ticketsPools[ticketsPool][
                0 : len(self.ticketsPools[ticketsPool]) - 1
            ]

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

            self.searchProcessPools[ticketsPool].start(
                "python",
                [
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
                    "--closeSession",
                    False,
                ],
            )


class authWindow(QtWidgets.QWidget):

    def __init__(self, args: arguments, mainWidget: mainWindow):
        super().__init__()

        self.setWindowTitle("GLPY - Auth")

        self.setMinimumSize(400, 300)

        self.layout = QtWidgets.QVBoxLayout(self)

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
        self.layout.addWidget(self.textEdit_url)

        self.textEdit_applicationToken = QtWidgets.QLineEdit(self)
        self.textEdit_applicationToken.setPlaceholderText("Application token")
        self.layout.addWidget(self.textEdit_applicationToken)

        self.widget_tokens = QtWidgets.QWidget(self)
        self.widget_tokens.layout = QtWidgets.QVBoxLayout(self.widget_tokens)

        self.textEdit_userToken = QtWidgets.QLineEdit(self.widget_tokens)
        self.textEdit_userToken.setPlaceholderText("User token")
        self.textEdit_userToken.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.widget_tokens.layout.addWidget(self.textEdit_userToken)
        self.layout.addWidget(self.widget_tokens)

        self.widget_credentials = QtWidgets.QWidget(self)
        self.widget_credentials.layout = QtWidgets.QVBoxLayout(self.widget_credentials)

        self.textEdit_username = QtWidgets.QLineEdit(self.widget_credentials)
        self.textEdit_username.setPlaceholderText("Username")
        self.textEdit_password = QtWidgets.QLineEdit(self.widget_credentials)
        self.textEdit_password.setPlaceholderText("Password")
        self.textEdit_password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.widget_credentials.layout.addWidget(self.textEdit_username)
        self.widget_credentials.layout.addWidget(self.textEdit_password)
        self.layout.addWidget(self.widget_credentials)

        self.label_errorMessage = QtWidgets.QLabel("")
        self.label_errorMessage.setStyleSheet("QLabel { color : red; }")
        self.label_errorMessage.setWordWrap(True)
        self.label_errorMessage.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
        self.label_errorMessage.hide()
        self.layout.addWidget(self.label_errorMessage)

        self.widget_controls = QtWidgets.QWidget(self)
        self.widget_controls.layout = QtWidgets.QHBoxLayout(self.widget_controls)

        self.pushButton_authenticate = QtWidgets.QPushButton(
            "Connect", self.widget_controls
        )
        self.pushButton_authenticate.clicked.connect(self.authenticate)

        self.pushButton_cancel = QtWidgets.QPushButton("Cancel", self.widget_controls)
        self.pushButton_cancel.clicked.connect(self.exit)

        self.widget_controls.layout.addWidget(self.pushButton_authenticate)
        self.widget_controls.layout.addWidget(self.pushButton_cancel)
        self.layout.addWidget(self.widget_controls)

    def authenticate(self):
        server = GLPIServer(self.textEdit_url.text())

        if len(self.textEdit_applicationToken.text()) > 0:
            server.setApplicationToken(self.textEdit_applicationToken.text())

        if len(self.textEdit_userToken.text()) > 0:
            try:
                server.authUsingToken(self.textEdit_userToken.text())
            except BaseException as e:
                if "ERROR_GLPI" in str(e):
                    self.label_errorMessage.setText(str(e))
                    self.label_errorMessage.show()
                return

            mainWidget.setServer(server)
            mainWidget.show()
            self.hide()
        elif (
            len(self.textEdit_username.text()) > 0
            and len(self.textEdit_password.text()) > 0
        ):
            try:
                server.authUsingCredentials(
                    self.textEdit_username.text(), self.textEdit_password.text()
                )
            except BaseException as e:
                if "ERROR_GLPI" in str(e):
                    self.label_errorMessage.setText(str(e))
                    self.label_errorMessage.show()
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

    ticketOptions = server.searchOptions(itemType="Ticket", raw=True)

    for category in ticketOptions.values():
        category = dict(category)
        # pprint(category)

        for optionName, value in category.items():
            # pprint(value["uid"].split(".")[-1:-2], sort_dicts=False)
            # if value["datatype"] == "dropdown":
            d = value["uid"].split(".")[-2]
            e = value["uid"].split(".")[-1]

            # t = server.getItem(d, itemID=0)

            print(optionName, ":", f"{d} -> {e}", value["available_searchtypes"])

    exit()

    isFound, message = server.deepSearchInTicket(
        text="test",
        ticketNumber=1,
        searchInReplies=True,
        searchInDOCX=True,
        searchInImages=True,
        searchInPDF=True,
        searchInUnknownFiles=True,
        searchInXLSX=True,
    )

    if isFound:
        print(message)
