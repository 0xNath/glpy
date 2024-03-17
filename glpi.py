import requests
import base64


class GLPI:
    def __init__(
        self,
        url: str = "",
        apiPath: str = "apirest.php",
    ) -> None:
        assert url != "", "Please provide the URL of the GLPI server."

        self.url = url
        self.apiPath = apiPath

        self.session = requests.Session()
        self.session.headers = {"Content-Type": "application/json"}

    def __del__(self) -> None:
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
            f"{self.url}/{self.apiPath}/initSession",
            params={"get_full_session": True},
        )

        if (not initSessionRequest.status_code == 200) or initSessionRequest.headers[
            "Content-Type"
        ] == "text/html; charset=UTF-8":
            raise BaseException(initSessionRequest.text)

        self.session.headers.pop("Authorization")

        self.session.headers.update(
            {
                "Session-Token": initSessionRequest.json()["session_token"],
            }
        )

    def search(self, itemType: str = "AllAssets") -> dict:
        searchRequest = self.session.get(f"{self.url}/{self.apiPath}/search/{itemType}")

        return searchRequest.json()

    def getItem(self, itemType: str, itemID: int) -> dict:
        getItemRequest = self.session.get(
            f"{self.url}/{self.apiPath}/{itemType}/{itemID}"
        )
        print(f"{self.url}/{self.apiPath}/{itemType}/{itemID}")

        return getItemRequest.json()

    def getMyEntities(self) -> dict:
        getMyProfilesRequest = self.session.get(
            f"{self.url}/{self.apiPath}/getMyProfiles"
        )

        return getMyProfilesRequest.json()

    def killSession(self) -> None:
        self.session.get(f"{self.url}/{self.apiPath}/killSession")
