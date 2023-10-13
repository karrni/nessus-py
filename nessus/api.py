import logging
import re
import time
from io import BytesIO
from json import JSONDecodeError
from typing import IO, Optional
from urllib.parse import urljoin

import requests

from . import constants as const
from .exceptions import NessusException
from .export import NessusScanExport
from .models import ScanCreateSettings, ScanFilters

logger = logging.getLogger(__name__)


class NessusAPI:
    """A Python wrapper for the Nessus API."""

    def __init__(
        self,
        url: str,
        *,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify: bool = False,
    ):
        # Ensure the base URL has a trailing /
        if not url.endswith("/"):
            url = f"{url}/"

        # Nessus
        self.base_url = url
        self._verify = verify
        self.__session = None

        # Authentication
        self._authenticated = False

        self._access_key = access_key
        self._secret_key = secret_key

        self._username = username
        self._password = password

    @property
    def _session(self):
        if self.__session is None:
            logger.debug("Initializing session")
            self.__session = requests.Session()
            self.__session.verify = self._verify
            self.__session.headers["X-API-Token"] = self._get_api_token()
        return self.__session

    def _get_api_token(self):
        """Extracts the API token from the 'nessus6.js' file."""

        logger.debug("Fetching API token from 'nessus6.js'")

        js_url = urljoin(self.base_url, "nessus6.js")
        js_text = self._session.get(js_url).text

        uuid_pattern = r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}"

        # The token is a UUID and hard-coded in the getApiToken() function
        token_pattern = rf'getApiToken"[^"]+"({uuid_pattern})'

        match = re.search(token_pattern, js_text)
        if not match:
            raise NessusException("Couldn't parse API token from nessus6.js")

        return match.group(1)

    def _authenticate(self):
        """Authenticate the instance using the api keys or credentials."""

        if self._access_key and self._secret_key:
            logger.debug("Authenticating using API keys")
            self._session.headers["X-ApiKeys"] = f"accessKey={self._access_key}; secretKey={self._secret_key}"
            self._authenticated = True

        elif self._username and self._password:
            logger.debug("Authenticating using credentials")
            response = self.session_create(self._username, self._password)
            self._session.headers["X-Cookie"] = f"token={response['token']}"
            self._authenticated = True

        else:
            raise NessusException("Either API keys or credentials must be provided before making a request")

    # ==============================
    #            REQUESTS
    # ==============================

    @staticmethod
    def _check_response(response: requests.Response):
        """Checks the response for errors."""

        # Check if the response code is 400 or above which indicates an error
        if not response.ok:
            try:
                # Nessus returns error messages in the 'error' key
                msg = response.json()["error"]

            # In case the response isn't JSON or doesn't have a message
            except (JSONDecodeError, KeyError):
                msg = "An error occurred"

            logger.error(f"Nessus returned an error: {msg}")
            raise NessusException(msg)

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        files: Optional[dict] = None,
        *,
        is_json: bool = True,
        download: bool = False,
        check_auth: bool = True,
    ):
        # Ensure the session was properly authenticated
        if check_auth and not self._authenticated:
            self._authenticate()

        # Log only the keys of 'params' and 'data' to avoid leaks in logs
        _params = list(params.keys()) if params else None
        _data = list(data.keys()) if data else None
        logger.debug(f"{method} {path}, params={_params} data={_data}")

        url = urljoin(self.base_url, path)

        # Set the content type to JSON if the request 'is_json', no files are
        # sent with it, and no headers were explicitly passed.
        if headers is None and is_json and not files:
            headers = {"Content-Type": "application/json"}

        try:
            response = self._session.request(
                method,
                url,
                params=params,
                json=data,
                headers=headers,
                files=files,
            )

        except requests.exceptions.ConnectionError as e:
            raise NessusException("Can't connect to Nessus, is the URL correct?") from e

        self._check_response(response)

        if download:
            return response.content

        return response.json()

    def _get(self, path: str, **kwargs):
        return self._request("GET", path, **kwargs)

    def _post(self, path: str, **kwargs):
        return self._request("POST", path, **kwargs)

    def _delete(self, path, **kwargs):
        return self._request("DELETE", path, **kwargs)

    def _put(self, path, **kwargs):
        return self._request("PUT", path, **kwargs)

    # ==============================
    #            EDITOR
    # ==============================

    def editor_list(self, template_type: str) -> dict:
        return self._get(f"editor/{template_type}/templates")

    def editor_details(self, template_type: str, template_uuid: str) -> dict:
        return self._get(f"editor/{template_type}/templates/{template_uuid}")

    # ==============================
    #            FOLDERS
    # ==============================

    def folders_list(self) -> dict:
        return self._get("folders")

    def folders_create(self, name: str) -> dict:
        if len(name) > const.MAX_FOLDER_NAME_LENGTH:
            raise NessusException(f"Folder name is too long, cannot exceed {const.MAX_FOLDER_NAME_LENGTH} characters")
        return self._post("folders", data={"name": name})

    def folders_edit(self, folder_id: int, name: str) -> dict:
        return self._put(f"folders/{folder_id}", data={"name": name})

    def folders_delete(self, folder_id: int) -> dict:
        return self._delete(f"folders/{folder_id}")

    # ==============================
    #             SCANS
    # ==============================

    def scans_list(self, folder_id: Optional[int] = None, last_modification_date: Optional[int] = None) -> dict:
        return self._get("scans", params={"folder_id": folder_id, "last_modification_date": last_modification_date})

    def scans_create(self, template_uuid: str, settings: ScanCreateSettings) -> dict:
        return self._post("/scans", data={"uuid": template_uuid, "settings": settings.model_dump()})

    def scans_copy(self, scan_id: int, folder_id: Optional[int] = None, name: Optional[str] = None) -> dict:
        return self._post(f"scans/{scan_id}/copy", data={"folder_id": folder_id, "name": name})

    def scans_delete(self, scan_id: int) -> dict:
        return self._delete(f"scans/{scan_id}")

    def scans_delete_bulk(self, ids: list[int]) -> dict:
        return self._delete("scans", data={"ids": ids})

    def scans_delete_history(self, scan_id: int, history_id: int) -> dict:
        return self._delete(f"scans/{scan_id}/history/{history_id}")

    def scans_details(
        self,
        scan_id: int,
        history_id: Optional[int] = None,
        limit: Optional[int] = None,
        filters: Optional[ScanFilters] = None,
    ) -> dict:
        params = {"history_id": history_id, "limit": limit}
        if filters is not None:
            params.update(filters.model_dump())
        return self._get(f"scans/{scan_id}", params=params)

    def scans_host_details(self, scan_id: int, host_id: int, history_id: Optional[int] = None) -> dict:
        return self._get(f"scans/{scan_id}/hosts/{host_id}", params={"history_id": history_id})

    def scans_plugin_details(self, scan_id: int, plugin_id: int, history_id: Optional[int] = None) -> dict:
        # undocumented
        return self._get(f"scans/{scan_id}/plugins/{plugin_id}", params={"history_id": history_id})

    def scans_compliance_details(self, scan_id: int, plugin_id: int, history_id: Optional[int] = None) -> dict:
        # undocumented
        return self._get(f"scans/{scan_id}/compliance/{plugin_id}", params={"history_id": history_id})

    def scans_host_plugin_details(
        self, scan_id: int, host_id: int, plugin_id: int, history_id: Optional[int] = None
    ) -> dict:
        return self._get(f"scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}", params={"history_id": history_id})

    def scans_schedule(self, scan_id: int, enabled: Optional[bool] = None) -> dict:
        return self._put(f"scans/{scan_id}/schedule", data={"enabled": enabled})

    def scans_launch(self, scan_id: int, alt_targets: Optional[list[str]] = None) -> dict:
        return self._post(f"scans/{scan_id}/launch", data={"alt_targets": alt_targets})

    def scans_pause(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/pause")

    def scans_resume(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/resume")

    def scans_stop(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/stop")

    def scans_kill(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/kill")

    def scans_import(self, file: str, folder_id: Optional[int] = None, password: Optional[str] = None) -> dict:
        return self._post("scans/import", data={"file": file, "folder_id": folder_id, "password": password})

    def scans_export_formats(self, scan_id: int, schedule_id: Optional[int] = None) -> dict:
        return self._get(f"scans/{scan_id}/export/formats", params={"schedule_id": schedule_id})

    def scans_export_request(self, scan_id: int, history_id: Optional[int] = None, format: str = "nessus") -> dict:
        # TODO has way more parameters
        return self._post(f"scans/{scan_id}/export", params={"history_id": history_id}, data={"format": format})

    def scans_export_status(self, scan_id: int, file_id: int) -> dict:
        return self._get(f"scans/{scan_id}/export/{file_id}/status")

    def scans_export_download(self, scan_id: int, file_id: int) -> dict:
        return self._get(f"scans/{scan_id}/export/{file_id}/download", download=True)

    # ==============================
    #             PLUGINS
    # ==============================

    def plugins_families(self) -> dict:
        return self._get("plugins/families")

    def plugins_family_details(self, family_id: int) -> dict:
        return self._get(f"plugins/families/{family_id}")

    def plugins_plugin_details(self, plugin_id: int) -> dict:
        return self._get(f"plugins/plugin/{plugin_id}")

    # ==============================
    #            POLICIES
    # ==============================

    def policies_list(self) -> dict:
        return self._get("policies")

    def policies_create(self) -> dict:
        raise NotImplementedError

    def policies_copy(self, policy_id: int) -> dict:
        return self._post(f"policies/{policy_id}/copy")

    def policies_configure(self) -> dict:
        raise NotImplementedError

    def policies_delete(self, policy_id: int) -> dict:
        return self._delete(f"policies/{policy_id}")

    def policies_delete_bulk(self, ids: list[int]) -> dict:
        return self._delete("policies", data={"ids": ids})

    def policies_details(self, policy_id: int) -> dict:
        return self._get(f"policies/{policy_id}")

    def policies_import(self):
        raise NotImplementedError

    def policies_export(self):
        raise NotImplementedError

    def policies_export_token_download(self):
        raise NotImplementedError

    # ==============================
    #              FILE
    # ==============================

    def file_upload(self, file_name: str, file_stream: IO, no_enc: Optional[int] = None) -> dict:
        files = {"Filedata": (file_name, file_stream)}
        return self._post("file/upload", data={"no_enc": no_enc}, files=files)

    # ==============================
    #             TOKENS
    # ==============================

    def tokens_status(self, token: str) -> dict:
        return self._get(f"tokens/{token}/status")

    def tokens_download(self, token: str) -> bytes:
        return self._get(f"tokens/{token}/download", download=True)

    # ==============================
    #            SESSION
    # ==============================

    def session_create(self, username: str, password: str) -> dict:
        return self._post("session", data={"username": username, "password": password}, check_auth=False)

    def session_get(self) -> dict:
        return self._get("session")

    # ==============================
    #            SERVER
    # ==============================

    def server_properties(self) -> dict:
        return self._get("server/properties")

    def server_status(self) -> dict:
        return self._get("server/status")

    # ==============================
    #        CUSTOM WRAPPERS
    # ==============================

    # --- Folders ---

    def get_folders(self) -> list[dict]:
        """Returns a list of all folders."""
        return self.folders_list()["folders"]

    def get_folder_name(self, folder_id: int) -> Optional[str]:
        """Returns the name of the folder."""
        for folder in self.get_folders():
            if folder["id"] == folder_id:
                return folder["name"]
        return None

    def get_folder_id(self, folder_name: str) -> Optional[int]:
        """Returns the ID of the folder."""
        for folder in self.get_folders():
            if folder["name"] == folder_name:
                return folder["id"]
        return None

    # --- Scans ---

    def get_scans(self) -> list[dict]:
        """Returns a list of all scans."""
        return self.scans_list()["scans"]

    def get_scan_details(self, scan_id: int, filters: Optional[ScanFilters] = None) -> dict:
        """Returns the details of the scan."""
        return self.scans_details(scan_id, filters=filters)

    def get_folder_scans(self, folder_id: int) -> list[dict]:
        """Returns a list of all scans in the folder."""
        return self.scans_list(folder_id=folder_id)["scans"]

    def get_scan_folder(self, scan_id: int) -> int:
        """Returns the ID of the folder the scan is located in."""
        return self.scans_details(scan_id)["info"]["folder_id"]

    def get_scan_name(self, scan_id: int) -> str:
        """Returns the name of the scan."""
        return self.scans_details(scan_id)["info"]["name"]

    # --- Plugins ---

    def get_plugin_details(self, scan_id: int, plugin_id: int) -> dict:
        """Returns the plugin details from the scan."""
        return self.scans_plugin_details(scan_id, plugin_id)

    def get_compliance_details(self, scan_id: int, plugin_id: int) -> dict:
        """Returns the compliance details from the scan."""
        return self.scans_compliance_details(scan_id, plugin_id)

    # --- Policies ---

    def get_policies(self) -> list[dict]:
        """Returns a list of all policies."""
        return self.policies_list()["policies"]

    def get_policy_uuid(self, policy_id: int) -> str:
        """Returns the UUID of the policy."""
        return self.policies_details(policy_id)["uuid"]

    def get_policy_id(self, policy_name: str) -> Optional[int]:
        """Returns the ID of the policy."""
        for policy in self.get_policies():
            if policy["name"] == policy_name:
                return policy["id"]
        return None

    # --- Import/Export ---

    def import_scan(self, file_name: str, file_stream: IO, folder_id: int):
        """Imports the scan into the folder."""
        temp_filename = self.file_upload(file_name, file_stream)["fileuploaded"]
        return self.scans_import(temp_filename, folder_id)

    def export_merged_scan(self, scan_ids: list[int], name: Optional[str] = None) -> BytesIO:
        """Exports multiple scans as .nessus files and merges them into one."""

        exported_scan = NessusScanExport(name)

        tokens = []

        # Trigger all exports and collect the tokens
        for scan_id in scan_ids:
            scan_details = self.get_scan_details(scan_id)

            for history_item in scan_details["history"]:
                history_id = history_item["history_id"]

                logger.debug(f"Triggering export of '{scan_id=}, {history_id=}'")

                token = self.scans_export_request(scan_id, history_id)["token"]
                tokens.append((token, scan_id, history_id))

        # Wait for each token to be ready, then download and merge them
        for token, scan_id, history_id in tokens:
            wait_time = 0
            timed_out = False

            logger.debug(f"Downloading export of '{scan_id=}, {history_id=}'")

            while True:
                status = self.tokens_status(token)["status"]
                if status == "ready":
                    break

                # Break out of the infinite loop and set the timeout flag
                if wait_time >= const.MAX_EXPORT_WAIT_TIME:
                    timed_out = True
                    break

                logger.debug(f"Export of '{scan_id=}, {history_id=}' not ready, waiting")
                time.sleep(const.EXPORT_WAIT_INTERVAL)
                wait_time += const.EXPORT_WAIT_INTERVAL

            # Skip if the download timed out
            if timed_out:
                logger.error(f"Export of '{scan_id=}, {history_id=}' timed out, skipping")
                continue

            # Write the scan data to a stream and add it to the export
            curr_data = self.tokens_download(token)
            curr_stream = BytesIO(curr_data)
            curr_stream.seek(0)

            exported_scan.add_scan(curr_stream)

        return exported_scan.get_stream()

    def export_scan(self, scan_id: int, name: Optional[str] = None) -> BytesIO:
        """Exports the scan as a .nessus file."""
        return self.export_merged_scan([scan_id], name)
