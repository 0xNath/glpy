import docx.document
import requests
import base64
import html
import re

import atexit
import pytesseract
from io import BytesIO
from typing import BinaryIO

from openpyxl import load_workbook
from docx import Document as docxDocument
from pypdf import PdfReader
from PIL import Image
from bs4 import BeautifulSoup


def verifyAuthentication(function):
    """Verify if the authentication against the server is done."""

    def verify(self, *args, **kargs):
        if not self._GLPI__authenticated:
            print(
                "You are not authenticated. "
                "Use argument -h/--help , or look at the online documentation https://github.com/0xNath/glpy for help."
            )
            exit(1)

        return function(self, *args, **kargs)

    return verify


class GLPI:
    """A class made to facilitate scripting with python against the GLPI REST API."""

    def __init__(
        self,
        url: str,
        APIPath: str = "/apirest.php",
    ) -> None:
        atexit.register(self.__close)

        self.url = url
        self.APIPath = APIPath

        self.__authenticated = False

        self.session = requests.Session()
        self.session.headers = {"Content-Type": "application/json"}

    def __close(self) -> None:
        if self.__authenticated:
            self.killSession()

    def authUsingCredentials(self, username: str, password: str):
        credentials = username + ":" + password
        encodedCredentials = base64.b64encode(credentials.encode()).decode("utf-8")

        self.session.headers.update({"Authorization": f"Basic {encodedCredentials}"})

        del credentials
        del encodedCredentials

        self.__initSession()

    def authUsingToken(self, userToken: str):
        self.session.headers.update({"Authorization": f"user_token {userToken}"})
        self.__initSession()

    def setApplicationToken(self, appToken: str):
        self.session.headers.update({"App-Token": appToken})

    def __initSession(self):
        initSessionRequest = self.session.get(
            f"{self.url}{self.APIPath}/initSession",
            params={"get_full_session": True},
        )

        if (not initSessionRequest.status_code == 200) or initSessionRequest.headers[
            "Content-Type"
        ] == "text/html; charset=UTF-8":
            result = initSessionRequest.json()
            raise BaseException(f"{result[0]} : {result[1]}")

        self.session.headers.pop("Authorization")

        self.session.headers.update(
            {
                "Session-Token": initSessionRequest.json()["session_token"],
            }
        )

        self.__authenticated = True

    def searchOptions(self, itemType: str = "AllAssets", raw: bool = False):

        parameters = {"raw": None} if raw else {}

        searchOptionsRequest = self.session.get(
            f"{self.url}{self.APIPath}/listSearchOptions/{itemType}",
            params=parameters,
        )

        if searchOptionsRequest.status_code == 200:
            return searchOptionsRequest.json()
        elif searchOptionsRequest.status_code == 401:
            raise searchOptionsRequest.json()
        else:
            raise BaseException(
                f"Unknow status code for this path : {searchOptionsRequest.status_code}.\n{searchOptionsRequest.json()}"
            )

    @verifyAuthentication
    def search(
        self,
        sort: int = 1,
        range: str = "0-49",
        rawdata: bool = False,
        withindexes: bool = False,
        uid_cols: bool = False,
        giveItems: bool = False,
        itemType: str = "AllAssets",
    ) -> dict:

        parameters = {
            "sort": sort,
            "range": range,
            "rawdata": rawdata,
            "withindexes": withindexes,
            "uid_cols": uid_cols,
            "giveItems": giveItems,
        }

        searchRequest = self.session.get(
            f"{self.url}{self.APIPath}/search/{itemType}", params=parameters
        )

        if searchRequest.status_code == 200:
            return searchRequest.json()
        elif searchRequest.status_code == 401:
            raise searchRequest.json()
        else:
            raise BaseException(
                f"Unknow status code for this path : {searchRequest.status_code}.\n{searchRequest.json()}"
            )

    @verifyAuthentication
    def getItem(self, itemType: str, itemID: int) -> dict:
        getItemRequest = self.session.get(
            f"{self.url}{self.APIPath}/{itemType}/{itemID}"
        )

        return getItemRequest.json()

    @verifyAuthentication
    def getSubItem(self, itemType: str, itemID: int, subItemType: str) -> dict:
        getItemRequest = self.session.get(
            f"{self.url}{self.APIPath}/{itemType}/{itemID}/{subItemType}"
        )

        return getItemRequest.json()

    @verifyAuthentication
    def getMyEntities(self, is_recursive: bool = False) -> str:

        parameters = {"is_recursive": is_recursive}

        getMyProfilesRequest = self.session.get(
            f"{self.url}{self.APIPath}/getMyProfiles", params=parameters
        )

        return getMyProfilesRequest.json()

    @verifyAuthentication
    def killSession(self) -> None:
        self.session.get(f"{self.url}{self.APIPath}/killSession")

    @verifyAuthentication
    def downloadDocument(self, documentID: int) -> BinaryIO:
        requestResponse = self.session.get(
            f"{self.url}{self.APIPath}/Document/{documentID}",
            headers={"Accept": "application/octet-stream"},
            stream=True,
        )

        if requestResponse.status_code == 200:
            return BytesIO(requestResponse.content)
        else:
            raise BaseException(requestResponse.json())

    def getTextFromImage(self, document: BinaryIO | bytes) -> str:
        if type(document) == bytes:
            document = BytesIO(document)
        return pytesseract.image_to_string(Image.open(document), lang="fre+eng")

    def parseAndSoupHTMLContent(self, text: str) -> str:
        return str(BeautifulSoup(html.unescape(text), features="html.parser"))

    def searchTextInItemDocuments(
        self, text: str, itemType: str, itemID: int
    ) -> tuple[bool, str]:
        for document in self.getSubItem(itemType, itemID, "Document"):
            if document["mime"].find("image") >= 0:
                textPosition = self.getTextFromImage(
                    self.downloadDocument(document["id"])
                ).find(text)

                if textPosition >= 0:
                    return (
                        True,
                        f"Found '{text}' in image '{document['name']}' at position {textPosition}.",
                    )
            elif document["mime"] == "application/pdf":
                reader = PdfReader(self.downloadDocument(document["id"]))

                for pagePosition in range(0, len(reader.pages)):
                    page = reader.pages[pagePosition]
                    textPosition = page.extract_text().find(text)

                    if textPosition >= 0:
                        return (
                            True,
                            f"Found '{text}' in pdf '{document['name']}' at page {pagePosition}, position {textPosition}.",
                        )

                    for image in page.images:
                        textPosition = self.getTextFromImage(image.data).find(text)

                        if textPosition >= 0:
                            return (
                                True,
                                f"Found '{text}' in pdf '{document['name']}' at page {pagePosition}, in image '{image.name}' at position {textPosition}.",
                            )

            elif document["filename"].find(".docx") >= 0:
                reader = docxDocument(self.downloadDocument(document["id"]))

                for p in reader.paragraphs:
                    textPosition = p.text.find(text)

                    if textPosition >= 0:
                        return (
                            True,
                            f"Found '{text}' in pdf '{document['name']}', position {textPosition}.",
                        )
            elif document["filename"].find(".xlsx") >= 0:
                wb = load_workbook(self.downloadDocument(document["id"]))

                for sheetName in wb.sheetnames:
                    sheet = wb[sheetName]
                    for row in range(1, sheet.max_row + 1):
                        for column in range(1, sheet.max_column + 1):
                            textPosition = str(sheet.cell(row, column).value).find(text)

                            if textPosition >= 0:
                                return (
                                    True,
                                    f"Found '{text}' in spreadsheet '{document['name']}', position {textPosition}.",
                                )

            else:
                print(document)

        return (False, "")

    @verifyAuthentication
    def deepSearchInTicket(
        self,
        text: str,
        ticketNumber: int,
        searchInImages: bool = False,
        searchInDOCX: bool = True,
        searchInXLSX: bool = True,
        searchInPDF: bool = True,
        searchInUnknownFiles: bool = True,
        followTicketLinks: bool = True,
        searchInReplies: bool = True,
    ) -> tuple[bool, str]:

        ticket = self.getItem("Ticket", itemID=ticketNumber)

        textPosition = self.parseAndSoupHTMLContent(ticket["name"]).find(text)

        if textPosition >= 0:
            return (
                True,
                f"Found '{text}' in ticket {ticket['id']} title at position {textPosition}.",
            )

        textPosition = self.parseAndSoupHTMLContent(ticket["content"]).find(text)

        if textPosition >= 0:
            return (
                True,
                f"Found '{text}' in ticket {ticket['id']} at position {textPosition}.",
            )

        foundInImage, imageSearchResult = self.searchTextInItemDocuments(
            itemType="Ticket", text=text, itemID=ticket["id"]
        )

        if foundInImage:
            return (
                True,
                f"Result found in ticket {ticketNumber} :\n{imageSearchResult}",
            )

        for subItemCategory in [
            "ITILFollowup",
            "TicketTask",
            "TicketValidation",
            "ITILSolution",
        ]:
            for subItem in self.getSubItem("Ticket", ticketNumber, subItemCategory):
                if subItemCategory == "TicketValidation":
                    textPosition = self.parseAndSoupHTMLContent(
                        subItem["comment_submission"]
                    ).find(text)
                else:
                    textPosition = self.parseAndSoupHTMLContent(
                        subItem["content"]
                    ).find(text)

                if textPosition >= 0:
                    return (
                        True,
                        f"Found '{text}' at position {textPosition} in {subItemCategory} {subItem['id']}.",
                    )

                foundInImage, imageSearchResult = self.searchTextInItemDocuments(
                    itemType=subItemCategory, text=text, itemID=subItem["id"]
                )

                if foundInImage:
                    return (
                        True,
                        f"Found '{text}' in {subItemCategory} {subItem['id']} :\n\t-{imageSearchResult}",
                    )

        return (False, "")
