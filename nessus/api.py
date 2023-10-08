import logging
import re
import time
from io import BytesIO
from json import JSONDecodeError
from typing import IO, Union
from urllib.parse import urljoin

import requests

from .exceptions import NessusException
from .export import NessusScanExport
from .types import TemplateType

logger = logging.getLogger(__name__)


class NessusAPI:
    def __init__(self, url: str, *, verify: bool = False):
        # Ensure the base URL has a trailing / so urljoin works properly
        if not url.endswith("/"):
            url = f"{url}/"

        self.url = url
        self._verify = verify
        self._is_authenticated = False

        self.__session = None

    @property
    def _session(self):
        if self.__session is None:
            logger.debug("Initializing session")
            self.__session = requests.Session()
            self.__session.verify = self._verify
            self._add_api_token()
        return self.__session

    def _add_api_token(self):
        logger.debug("Fetching API token from 'nessus6.js'")

        js_url = urljoin(self.url, "nessus6.js")
        js_text = self._session.get(js_url).text

        uuid_pattern = r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}"
        token_pattern = rf'getApiToken"[^"]+"({uuid_pattern})'

        match = re.search(token_pattern, js_text)
        if not match:
            raise NessusException("Couldn't parse API token from nessus6.js")

        self._session.headers["X-Cookie"] = match.group(1)

    # ==============================
    #         AUTHENTICATION
    # ==============================

    @classmethod
    def with_keys(cls, url: str, access_key: str, secret_key: str, *, verify: bool = False) -> "NessusAPI":
        instance = cls(url, verify=verify)
        instance.add_keys(access_key, secret_key)
        return instance

    @classmethod
    def with_credentials(cls, url: str, username: str, password: str, *, verify: bool = False) -> "NessusAPI":
        instance = cls(url, verify=verify)
        instance.add_credentials(username, password)
        return instance

    def add_keys(self, access_key: str, secret_key: str):
        self._session.headers["X-ApiKeys"] = f"accessKey={access_key}; secretKey={secret_key}"
        self._is_authenticated = True

    def add_credentials(self, username: str, password: str):
        response = self.session_create(username, password)
        self._session.headers["X-Cookie"] = f"token={response['token']}"
        self._is_authenticated = True

    # ==============================
    #            REQUESTS
    # ==============================

    def _check_authentication(self):
        if not self._is_authenticated:
            raise NessusException("NessusAPI instance is not authenticated")

    @staticmethod
    def _check_response(response: requests.Response):
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
        params: Union[dict, None] = None,
        data: Union[dict, None] = None,
        headers: Union[dict, None] = None,
        files: Union[dict, None] = None,
        *,
        is_json: bool = True,
        download: bool = False,
        check_auth: bool = True,
    ):
        if check_auth:
            self._check_authentication()

        url = urljoin(self.url, path)

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
        logger.debug(f"GET {path=}, {kwargs.keys()}")
        return self._request("GET", path, **kwargs)

    def _post(self, path: str, **kwargs):
        logger.debug(f"POST {path=}, {kwargs.keys()}")
        return self._request("POST", path, **kwargs)

    def _delete(self, path, **kwargs):
        logger.debug(f"DELETE {path=}, {kwargs.keys()}")
        return self._request("DELETE", path, **kwargs)

    def _put(self, path, **kwargs):
        logger.debug(f"PUT {path=}, {kwargs.keys()}")
        return self._request("PUT", path, **kwargs)

    # ==============================
    #            EDITOR
    # ==============================

    def editor_list(self, template_type: TemplateType) -> dict:
        return self._get(f"editor/{template_type}/templates")

    def editor_details(self, template_type: TemplateType, template_uuid: str) -> dict:
        return self._get(f"editor/{template_type}/templates/{template_uuid}")

    # ==============================
    #            FOLDERS
    # ==============================

    def folders_list(self) -> dict:
        return self._get("folders")

    def folders_create(self, name: str) -> dict:
        return self._post("folders", data={"name": name})

    def folders_edit(self, folder_id: int, name: str) -> dict:
        return self._put(f"folders/{folder_id}", data={"name": name})

    def folders_delete(self, folder_id: int) -> dict:
        return self._delete(f"folders/{folder_id}")

    # ==============================
    #             SCANS
    # ==============================

    def scans_list(self, folder_id: Union[int, None] = None, last_modification_date: Union[int, None] = None) -> dict:
        return self._get("scans", params={"folder_id": folder_id, "last_modification_date": last_modification_date})

    def scans_create(self) -> dict:
        raise NotImplementedError

    def scans_copy(self, scan_id: int, folder_id: Union[int, None] = None, name: Union[str, None] = None) -> dict:
        return self._post(f"scans/{scan_id}/copy", data={"folder_id": folder_id, "name": name})

    def scans_delete(self, scan_id: int) -> dict:
        return self._delete(f"scans/{scan_id}")

    def scans_delete_bulk(self, ids: list[int]) -> dict:
        return self._delete("scans", data={"ids": ids})

    def scans_delete_history(self, scan_id: int, history_id: int) -> dict:
        return self._delete(f"scans/{scan_id}/history/{history_id}")

    def scans_details(self, scan_id: int, history_id: Union[int, None] = None, limit: Union[int, None] = None) -> dict:
        return self._get(f"scans/{scan_id}", params={"history_id": history_id, "limit": limit})

    def scans_host_details(self, scan_id: int, host_id: int, history_id: Union[int, None] = None) -> dict:
        return self._get(f"scans/{scan_id}/hosts/{host_id}", params={"history_id": history_id})

    def scans_plugin_details(self, scan_id: int, plugin_id: int, history_id: Union[int, None] = None) -> dict:
        # undocumented
        return self._get(f"scans/{scan_id}/plugins/{plugin_id}", params={"history_id": history_id})

    def scans_compliance_details(self, scan_id: int, plugin_id: int, history_id: Union[int, None] = None) -> dict:
        # undocumented
        return self._get(f"scans/{scan_id}/compliance/{plugin_id}", params={"history_id": history_id})

    def scans_host_plugin_details(
        self, scan_id: int, host_id: int, plugin_id: int, history_id: Union[int, None] = None
    ) -> dict:
        return self._get(f"scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}", params={"history_id": history_id})

    def scans_schedule(self, scan_id: int, enabled: Union[bool, None] = None) -> dict:
        return self._put(f"scans/{scan_id}/schedule", data={"enabled": enabled})

    def scans_launch(self, scan_id: int, alt_targets: Union[list[str], None] = None) -> dict:
        return self._post(f"scans/{scan_id}/launch", data={"alt_targets": alt_targets})

    def scans_pause(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/pause")

    def scans_resume(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/resume")

    def scans_stop(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/stop")

    def scans_kill(self, scan_id: int) -> dict:
        return self._post(f"scans/{scan_id}/kill")

    def scans_import(self, file: str, folder_id: Union[int, None] = None, password: Union[str, None] = None) -> dict:
        return self._post("scans/import", data={"file": file, "folder_id": folder_id, "password": password})

    def scans_export_formats(self, scan_id: int, schedule_id: Union[int, None] = None) -> dict:
        return self._get(f"scans/{scan_id}/export/formats", params={"schedule_id": schedule_id})

    def scans_export_request(self, scan_id: int, history_id: Union[int, None] = None, format: str = "nessus") -> dict:
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

    def file_upload(self, file_name: str, file_stream: IO, no_enc: Union[int, None] = None) -> dict:
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

    def get_folders(self) -> Union[list[dict], None]:
        return self.folders_list()["folders"]

    def get_folder_name(self, folder_id: int) -> Union[str, None]:
        for folder in self.folders_list():
            if folder["id"] == folder_id:
                return folder["name"]
        return None

    def get_folder_id(self, folder_name: str) -> Union[int, None]:
        for folder in self.folders_list():
            if folder["name"] == folder_name:
                return folder["id"]
        return None

    # --- Scans ---

    def get_scans(self) -> Union[list[dict], None]:
        return self.scans_list()["scans"]

    def get_scan_details(self, scan_id: int) -> dict:
        return self.scans_details(scan_id)

    def get_folder_scans(self, folder_id: int) -> Union[list[dict], None]:
        return self.scans_list(folder_id=folder_id)["scans"]

    def get_scan_folder(self, scan_id: int) -> int:
        return self.scans_details(scan_id)["info"]["folder_id"]

    def get_scan_name(self, scan_id: int) -> str:
        return self.scans_details(scan_id)["info"]["name"]

    # --- Plugins ---

    def get_plugin_details(self, scan_id: int, plugin_id: int) -> dict:
        return self.scans_plugin_details(scan_id, plugin_id)

    def get_compliance_details(self, scan_id: int, plugin_id: int) -> dict:
        return self.scans_compliance_details(scan_id, plugin_id)

    # --- Policies ---

    def get_policies(self) -> Union[list[dict], None]:
        return self.policies_list()["policies"]

    def get_policy_uuid(self, policy_id: int) -> str:
        return self.policies_details(policy_id)["uuid"]

    def get_policy_id(self, policy_name: str) -> Union[int, None]:
        for policy in self.policies_list():
            if policy["name"] == policy_name:
                return policy["id"]
        return None

    # --- Import/Export ---

    def import_scan(self, file_name: str, file_stream: IO, folder_id: int):
        temp_filename = self.file_upload(file_name, file_stream)["fileuploaded"]
        return self.scans_import(temp_filename, folder_id)

    def _export_scan_item(self, scan_id: int, history_id: int) -> BytesIO:
        token = self.scans_export_request(scan_id, history_id)["token"]
        while self.tokens_status(token)["status"] != "ready":
            time.sleep(2)

        file_bytes = self.tokens_download(token)
        file_stream = BytesIO()
        file_stream.write(file_bytes)
        file_stream.seek(0)
        return file_stream

    def export_merged_scan(self, scan_ids: list[int], name: Union[str, None] = None) -> BytesIO:
        scan_export = NessusScanExport(name)

        for scan_id in scan_ids:
            scan_details = self.get_scan_details(scan_id)

            for history_item in scan_details["history"]:
                if history_item["status"] in ("completed", "imported", "canceled"):
                    export_item = self._export_scan_item(scan_id, history_item["history_id"])
                    scan_export.add_scan(export_item)

        return scan_export.get_stream()

    def export_scan(self, scan_id: int, name: Union[str, None] = None) -> BytesIO:
        return self.export_merged_scan([scan_id], name)
