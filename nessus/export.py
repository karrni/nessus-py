import xml.etree.ElementTree as ET
from io import BytesIO, IOBase
from typing import IO, Union

from defusedxml.ElementTree import fromstring, parse


class NessusScanExport:
    """
    An XML Nessus export typically consists of a top-level "NessusClientData_v2"
    element, which contains a "Report" element and various other elements such
    as "Policy" and "Preferences".

    The "Report" element contains a list of "ReportHost" elements, each of which
    represents a single host that was scanned. Each "ReportHost" element has a
    "name" attribute that specifies the hostname or IP address of the host, and
    it contains a list of "ReportItem" elements, which represent vulnerabilities
    or other findings discovered on the host.

    Each "ReportItem" element has a number of attributes that provide details
    about the finding, such as the port number, plugin ID, severity, and a
    description. It may also contain additional elements such as "plugin_output"
    or "description" that provide more information about the finding.

    Here is an example of the structure of an XML Nessus export:

    <NessusClientData_v2>
      <Report>
        <ReportHost name="192.168.1.1">
          <ReportItem pluginID="12345" port="80" severity="3">
            <description>Vulnerability description goes here</description>
            <plugin_output>Additional details about the vulnerability</plugin_output>
          </ReportItem>
          <ReportItem pluginID="12346" port="443" severity="2">
            <description>Vulnerability description goes here</description>
            <plugin_output>Additional details about the vulnerability</plugin_output>
          </ReportItem>
        </ReportHost>
        <ReportHost name="192.168.1.2">
          <ReportItem pluginID="12347" port="22" severity="1">
            <description>Vulnerability description goes here</description>
            <plugin_output>Additional details about the vulnerability</plugin_output>
          </ReportItem>
        </ReportHost>
      </Report>
      <Policy>
        <!-- Policy details go here -->
      </Policy>
      <Preferences>
        <!-- Preferences details go here -->
      </Preferences>
    </NessusClientData_v2>
    """

    def __init__(self, name: Union[str, None] = None):
        if name is None:
            name = "Merged Report"

        self.root = ET.Element("NessusClientData_v2")
        self.report = ET.SubElement(self.root, "Report")
        self.report.attrib["name"] = name

        # Keep track of existing hosts
        self.seen_hosts = {}

    @staticmethod
    def _load_tree(data: Union[str, IO]):
        if isinstance(data, str):
            return fromstring(data)

        if isinstance(data, IOBase):
            if data.tell() != 0:
                data.seek(0)

            return parse(data)

        raise ValueError("Invalid nessus scan")

    def set_name(self, name: str):
        self.report.attrib["name"] = name

    def add_scan(self, scan_export: Union[str, IO]):
        tree = self._load_tree(scan_export)
        report = tree.find("Report")

        # Loop over all hosts in the new scan
        for host in report.findall("ReportHost"):
            hostname = host.attrib["name"]

            # If the host is new append it to the report
            if hostname not in self.seen_hosts:
                self.seen_hosts[hostname] = host
                self.report.append(host)
                continue

            # If the host already exists merge the items
            existing_host = self.seen_hosts[hostname]

            for item in host.findall("ReportItem"):
                port = item.attrib["port"]
                plugin_id = item.attrib["pluginID"]
                selector = f"ReportItem[@port='{port}'][@pluginID='{plugin_id}']"

                # Add the item to the host if it doesn't already exist
                existing_item = existing_host.find(selector)
                if existing_item is None:
                    existing_host.append(item)

    def get_stream(self):
        tree = ET.ElementTree(self.root)
        stream = BytesIO()
        tree.write(stream, encoding="utf-8", xml_declaration=True)
        stream.seek(0)
        return stream
