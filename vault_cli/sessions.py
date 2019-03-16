import requests
import urllib3


class Session(requests.Session):
    """A wrapper for requests.Session to override 'verify' property, ignoring
    REQUESTS_CA_BUNDLE environment variable.

    This is a workaround for
    https://github.com/requests/requests/issues/3829
    """

    def merge_environment_settings(self, url, proxies, stream, verify, *args, **kwargs):
        if self.verify is False:
            verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        return super(Session, self).merge_environment_settings(
            url, proxies, stream, verify, *args, **kwargs
        )
