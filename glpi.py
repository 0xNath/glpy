import requests
import base64
import html
import re
from PIL import Image
from bs4 import BeautifulSoup
import atexit
import pytesseract
from io import BytesIO


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
    def deepSearchInTicket(
        self,
        text: str,
        ticketNumber: int,
        searchInPictures: bool = False,
        searchInDOCX: bool = True,
        searchInXLSX: bool = True,
        searchInPDF: bool = True,
        searchInUnknownFiles: bool = True,
        followTicketLinks: bool = True,
        searchInReplies: bool = True,
    ) -> bool:

        ticket = self.getItem("Ticket", itemID=ticketNumber)

        ticket["content"] = str(html.unescape(ticket["content"]))

        soup = BeautifulSoup(ticket["content"], features="html.parser")

        textPosition = ticket["content"].find(text)

        if textPosition >= 0:
            print(f"Found '{text}' in ticket Content at position {textPosition}.")
            return True

        if searchInPictures:
            for image in soup.find_all("img"):

                if image["src"].find("http") == 0:
                    src = image["src"]
                else:
                    src = self.url + image["src"]

                requestResponse = self.session.get(f"{src}", stream=True)

                imageFileStream = BytesIO(requestResponse.content)

                textFromImage = str(
                    pytesseract.image_to_string(Image.open(imageFileStream))
                )

                textPosition = textFromImage.find(text)

                if textPosition >= 0:
                    print(
                        f"Found '{text}' in image at position {textPosition} :\n{src}\n{textFromImage}"
                    )
                    return True

        return False
