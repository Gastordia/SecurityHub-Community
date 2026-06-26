"""
Register all parsers in the registry
"""

from .registry import ParserRegistry
from .nmap.parser import NmapParser
from .nexpose.parser import NexposeParser
from .burp.parser import BurpParser
from .appspider.parser import AppSpiderParser
from .nessus.parser import NessusParser
from .openvas.parser import OpenVASParser
from .zap.parser import ZAPParser
from .nuclei.parser import NucleiParser
from .acunetix.parser import AcunetixParser
from .qualys.parser import QualysParser
from .sarif.parser import SARIFParser
from .trivy.parser import TrivyParser


def register_all_parsers():
    """Register all built-in parsers, then load any active custom parsers from the DB."""

    ParserRegistry.register("nmap", NmapParser)
    ParserRegistry.register("nessus", NessusParser)
    ParserRegistry.register("openvas", OpenVASParser)
    ParserRegistry.register("burp", BurpParser)
    ParserRegistry.register("zap", ZAPParser)
    ParserRegistry.register("nuclei", NucleiParser)
    ParserRegistry.register("acunetix", AcunetixParser)
    ParserRegistry.register("nexpose", NexposeParser)
    ParserRegistry.register("appspider", AppSpiderParser)
    ParserRegistry.register("qualys", QualysParser)
    ParserRegistry.register("sarif", SARIFParser)
    ParserRegistry.register("trivy", TrivyParser)

    _load_custom_parsers()

    print(f"Registered {len(ParserRegistry.list_parsers())} parsers:")
    for parser_type in ParserRegistry.list_parsers():
        metadata = ParserRegistry.get_metadata(parser_type)
        print(f"  - {parser_type}: {metadata.name} ({', '.join(metadata.supported_formats)})")


def _load_custom_parsers():
    """Custom parser builder is not available in this release."""
    pass


def get_registered_parsers():
    """Get list of registered parsers with metadata"""
    parsers = {}
    for parser_type in ParserRegistry.list_parsers():
        metadata = ParserRegistry.get_metadata(parser_type)
        parsers[parser_type] = {
            'name': metadata.name,
            'version': metadata.version,
            'description': metadata.description,
            'supported_formats': metadata.supported_formats,
            'author': metadata.author,
            'website': metadata.website
        }
    return parsers

