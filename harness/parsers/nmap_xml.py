from pathlib import Path
import hashlib
import xml.etree.ElementTree as ET

from harness.models.finding import Evidence, Finding


class NmapXMLParser:
    tool_name = "nmap"

    def can_parse(self, path: Path, content: str) -> bool:
        return (
            path.suffix.lower() == ".xml"
            and "<nmaprun" in content[:1000]
        )

    def parse(self, path: Path, content: str) -> list[Finding]:
        root = ET.fromstring(content)
        findings: list[Finding] = []

        for host in root.findall("host"):
            address_node = host.find("address")
            if address_node is None:
                continue

            asset = address_node.attrib.get("addr", "unknown")
            ports = host.find("ports")

            if ports is None:
                continue

            for port_node in ports.findall("port"):
                state_node = port_node.find("state")
                service_node = port_node.find("service")

                port = int(port_node.attrib["portid"])
                protocol = port_node.attrib.get("protocol")
                state = (
                    state_node.attrib.get("state")
                    if state_node is not None
                    else "unknown"
                )

                service = None
                service_data = {}

                if service_node is not None:
                    service = service_node.attrib.get("name")
                    service_data = dict(service_node.attrib)

                scripts = []
                for script in port_node.findall("./script"):
                    scripts.append({
                        "id": script.attrib.get("id"),
                        "output": script.attrib.get("output"),
                    })

                observed = {
                    "port_state": state,
                    "service": service_data,
                    "scripts": scripts,
                }

                title = f"Nmap service observation: {service or 'unknown'}"
                raw_fragment = ET.tostring(
                    port_node,
                    encoding="unicode",
                )

                fingerprint_input = (
                    f"{asset}|{protocol}|{port}|{service}|{state}|"
                    f"{scripts}"
                )
                fingerprint = hashlib.sha256(
                    fingerprint_input.lower().encode()
                ).hexdigest()[:16]

                evidence_id = hashlib.sha256(
                    f"{path}:{asset}:{port}:{raw_fragment}".encode()
                ).hexdigest()[:16]

                findings.append(
                    Finding(
                        finding_id=f"f-{fingerprint}",
                        asset=asset,
                        asset_type="host",
                        port=port,
                        protocol=protocol,
                        service=service,
                        title=title,
                        description=(
                            f"Nmap observed port {port}/{protocol} "
                            f"in state {state}."
                        ),
                        tags=["nmap", state],
                        source_tools=[self.tool_name],
                        fingerprint=fingerprint,
                        evidence=[
                            Evidence(
                                evidence_id=f"e-{evidence_id}",
                                source_tool=self.tool_name,
                                source_file=str(path),
                                raw_text=raw_fragment,
                                structured_data=observed,
                            )
                        ],
                    )
                )

        return findings