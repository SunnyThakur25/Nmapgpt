import xml.etree.ElementTree as ET
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NmapParser:
    """
    Parse Nmap XML scan results into a structured format.
    """
    def __init__(self, xml_file: str):
        self.xml_file = xml_file

    def parse(self) -> Dict[str, Any]:
        """
        Parse Nmap XML file and extract hosts, ports, services, and OS details.

        Returns:
            Dict[str, Any]: Structured data of scan results
        """
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()
            services = {}

            for host in root.findall('host'):
                address = host.find('address').get('addr')
                services[address] = {'ports': {}, 'os': {}}

                # Parse ports and services
                for port in host.find('ports').findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state').get('state')
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    version = service.get('product', '') + ' ' + service.get('version', '') if service is not None else ''

                    services[address]['ports'][port_id] = {
                        'protocol': protocol,
                        'state': state,
                        'service': service_name,
                        'version': version.strip()
                    }

                # Parse OS details
                osmatch = host.find('os/osmatch')
                if osmatch is not None:
                    services[address]['os'] = {
                        'name': osmatch.get('name', ''),
                        'accuracy': osmatch.get('accuracy', '')
                    }

            logger.info(f"Parsed Nmap XML: {self.xml_file}")
            return services
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {str(e)}")
            raise
