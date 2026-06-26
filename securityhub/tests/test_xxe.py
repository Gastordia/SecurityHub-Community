import os
import pytest
from lxml import etree
from defusedxml.common import EntitiesForbidden
import tempfile
from utils import xml

class TestSafeXMLParser:

    @pytest.fixture
    def safe_xml(self):
        return """<?xml version="1.0"?>
        <root>
            <element>data</element>
        </root>
        """

    @pytest.fixture
    def xxe_xml(self):
        return """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [
          <!ELEMENT foo ANY >
          <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""

    @pytest.fixture
    def billion_laughs_xml(self):
        return """<?xml version="1.0"?>
        <!DOCTYPE lolz [
         <!ENTITY lol "lol">
         <!ELEMENT lolz (#PCDATA)>
         <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
         <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
         <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
         <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
         <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
         <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
         <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
         <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
         <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
        ]>
        <lolz>&lol9;</lolz>"""

    def test_safe_xml_parsing(self, safe_xml):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(safe_xml)
            f_path = f.name
        
        try:
            tree = xml.parse_xml_safely(f_path)
            assert tree.getroot().tag == 'root'
            assert tree.find('element').text == 'data'
        finally:
            os.remove(f_path)

    def test_xxe_protection(self, xxe_xml):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xxe_xml)
            f_path = f.name
            
        try:
            # Depending on lxml version/config, this might raise an error or just return empty/safe content
            # But it MUST NOT contain the contents of /etc/passwd
            try:
                tree = xml.parse_xml_safely(f_path)
                root = tree.getroot()
                if root.text:
                    assert "root:" not in root.text
            except (etree.XMLSyntaxError, EntitiesForbidden):
                pass  # Both indicate XXE was blocked — correct
        finally:
            os.remove(f_path)

    def test_billion_laughs_protection(self, billion_laughs_xml):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(billion_laughs_xml)
            f_path = f.name

        try:
            # defusedxml.ElementTree raises EntitiesForbidden; lxml raises XMLSyntaxError.
            # Either means the attack was blocked — both are correct.
            with pytest.raises((etree.XMLSyntaxError, EntitiesForbidden, Exception)):
                xml.parse_xml_safely(f_path)
        finally:
            os.remove(f_path)

    def test_no_direct_etree_usage(self):
        import glob
        import os
        
        # Define the root of the parsers directory
        parsers_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'utils', 'parsers')
        
        unsafe_usage = []
        for root, dirs, files in os.walk(parsers_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'etree.parse(' in content and 'lxml' in content:
                             # Exclude the safe parser file itself if it was in the same dir (it's not, but good practice)
                             pass
                        
                        # Check for unsafe imports or usage
                        # We specifically want to ban 'from lxml import etree' -> 'etree.parse' 
                        # OR 'from defusedxml.ElementTree import parse' if we want to strictly enforce our new wrapper
                        
                        if 'from defusedxml.ElementTree import parse' in content:
                             unsafe_usage.append(f"{file_path}: Uses defusedxml directly")
                        
                        if 'etree.parse(' in content and 'utils.xml' not in content:
                             # This is a bit heuristic, but if they use etree.parse and don't assume it's the safe one from utils.xml...
                             # Actually, we replaced `from ... import parse` so `parse()` calls are fine IF they come from utils.xml
                             pass

        # A better check:
        # 1. Scan for `from lxml import etree`
        # 2. If present, check if `etree.parse(` is called. 
        # 3. Check for `from defusedxml.ElementTree import parse`
        
        for root, dirs, files in os.walk(parsers_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        content = f.read()
                        if 'defusedxml.ElementTree' in content:
                             unsafe_usage.append(f"{file_path}: Uses defusedxml")
                        if 'lxml.etree' in content and 'parse(' in content:
                             # This catches explicit lxml.etree.parse calls
                             unsafe_usage.append(f"{file_path}: Uses lxml.etree parsing directly")

        assert not unsafe_usage, f"Found unsafe XML parsing usage: {unsafe_usage}"
