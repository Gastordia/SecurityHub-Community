import logging
from defusedxml import ElementTree as safe_ET
from xml.etree.ElementTree import ParseError

logger = logging.getLogger(__name__)


def parse_xml_safely(file_path):
    """
    Safely parse an XML file using defusedxml.

    Uses defusedxml.ElementTree which patches Python's standard library parser
    to prevent XXE, entity expansion, and related attacks:
    - External entity resolution disabled
    - Network access disabled
    - DTD processing disabled

    Returns an xml.etree.ElementTree.ElementTree compatible object.
    All parsers use only standard ElementTree methods (getroot, findall, find,
    attrib, tag, text) so lxml-specific APIs are not needed.
    """
    try:
        return safe_ET.parse(file_path)
    except ParseError as e:
        logger.warning(
            "Rejected unsafe or malformed XML input",
            extra={"file": file_path, "reason": str(e)}
        )
        raise
    except Exception as e:
        logger.error(
            "Error parsing XML file",
            extra={"file": file_path, "error": str(e)}
        )
        raise
