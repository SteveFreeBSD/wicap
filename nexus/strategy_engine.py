"""
NEXUS Strategy Engine
Intelligent Attack Planning for WPA Cracking.

Dynamically generates attack rounds based on target intelligence (SSID, Vendor, Patterns).
"""
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class TargetIntelligence:
    """Encapsulates all known intel about a target."""
    ssid: str | None = None
    bssid: str | None = None
    priority_score: int = 50
    captured_visuals: list[str] = None # e.g. OCR text from login portal? Future.

@dataclass
class AttackRound:
    name: str
    strategy: str
    timeout_sec: int
    description: str
    min_priority: int = 0
    config: dict[str, Any] | None = None

class StrategyEngine:
    # Comprehensive OUI Database - IEEE Registry with 38,704 vendor entries
    # Imported from centralized database for consistency across all WICAP modules
    from .oui_database import OUI_DATABASE as OUI_DB_RAW

    # Convert to format used by strategy engine (no colons in OUI key)
    OUI_DB = {k.replace(':', ''): v for k, v in OUI_DB_RAW.items()}

    def __init__(self):
        # Vendor-specific attack patterns
        self.vendor_patterns = {
            'Netgear': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Netgear 8-digit Adj+Noun', 'mode': 'mask'},
            'TP-Link': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'TP-Link 8-digit', 'mode': 'mask'},
            'Linksys': {'mask': '?d?d?d?d?d', 'desc': 'Legacy Linksys 5-digit', 'mode': 'mask'},
            'Google': {'mask': '?d?d?d?d?d?d?d?d?d?d', 'desc': 'Google Fiber 10-digit', 'mode': 'mask'},
            'Nest': {'mask': '?d?d?d?d?d?d?d?d?d?d', 'desc': 'Nest 10-digit', 'mode': 'mask'},
            'Xfinity': {'mask': '?u?u?u?d?d?d?d', 'desc': 'Xfinity/Technicolor (e.g. CGF1234)', 'mode': 'mask'},
            'Asus': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Asus Default 8-digit', 'mode': 'mask'},
            'D-Link': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'D-Link 8-digit', 'mode': 'mask'},
            'Belkin': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Belkin 8-digit', 'mode': 'mask'},
            'Arris': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Arris Cable Modem 8-digit', 'mode': 'mask'},
            'Motorola': {'mask': '?d?d?d?d?d?d?d?d?d?d', 'desc': 'Motorola 10-digit', 'mode': 'mask'},
            'Actiontec': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Verizon/Actiontec 8-digit', 'mode': 'mask'},
            'Tenda': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Tenda 8-digit', 'mode': 'mask'},
            'Huawei': {'mask': '?d?d?d?d?d?d?d?d', 'desc': 'Huawei 8-digit', 'mode': 'mask'},
        }

        # Comprehensive semantic categories
        self.semantic_map = {
            # Food & Beverage
            'cafe': ['coffee', 'latte', 'espresso', 'wifi', 'beans', 'brewing', 'roast', 'barista', 'mocha', 'cappuccino'],
            'coffee': ['cafe', 'latte', 'espresso', 'mocha', 'brew', 'beans', 'roast', 'java', 'starbucks'],
            'pizza': ['pepperoni', 'cheese', 'slice', 'delivery', 'oven', 'crust', 'italian', 'dominos', 'papa'],
            'bar': ['beer', 'drink', 'wine', 'cocktail', 'pub', 'liquor', 'tavern', 'shots', 'happy', 'hour'],
            'restaurant': ['food', 'dining', 'menu', 'chef', 'kitchen', 'eat', 'grill', 'bistro', 'diner'],
            'bakery': ['bread', 'pastry', 'cake', 'cookie', 'sweet', 'fresh', 'oven', 'flour'],

            # Retail
            'store': ['shop', 'retail', 'sale', 'buy', 'mall', 'outlet', 'plaza', 'market'],
            'shop': ['store', 'retail', 'buy', 'sale', 'boutique', 'mart', 'depot'],
            'mall': ['shopping', 'store', 'plaza', 'center', 'retail', 'outlet'],

            # Hospitality
            'hotel': ['room', 'guest', 'lobby', 'suite', 'inn', 'resort', 'stay', 'vacation', 'travel'],
            'motel': ['room', 'guest', 'stay', 'travel', 'inn', 'lodge'],
            'resort': ['vacation', 'pool', 'spa', 'beach', 'hotel', 'relax', 'paradise'],
            'guest': ['visitor', 'welcome', 'password', 'internet', 'access', 'wifi', 'free', 'lobby'],

            # Corporate / Office
            'office': ['work', 'business', 'secure', 'staff', 'employee', 'corp', 'company', 'enterprise'],
            'corp': ['corporate', 'business', 'office', 'company', 'enterprise', 'inc', 'llc'],
            'business': ['office', 'work', 'corporate', 'professional', 'enterprise', 'company'],
            'conference': ['meeting', 'room', 'event', 'seminar', 'convention', 'summit'],

            # Education
            'school': ['student', 'teacher', 'class', 'learn', 'education', 'campus', 'library'],
            'university': ['campus', 'student', 'college', 'library', 'dorm', 'academic'],
            'library': ['books', 'study', 'quiet', 'read', 'research', 'academic'],

            # Healthcare
            'hospital': ['health', 'patient', 'care', 'medical', 'clinic', 'doctor', 'nurse'],
            'clinic': ['health', 'medical', 'doctor', 'patient', 'care', 'wellness'],
            'dental': ['teeth', 'smile', 'care', 'health', 'clinic', 'doctor'],

            # Residential
            'home': ['family', 'house', 'wifi', 'love', 'welcome', 'sweet', 'network', 'private'],
            'family': ['home', 'house', 'kids', 'love', 'wifi', 'private', 'secure'],
            'apartment': ['home', 'unit', 'flat', 'residence', 'apt', 'building'],

            # Mobile / Hotspot
            'mobile': ['iphone', 'android', 'hotspot', 'samsung', 'pixel', 'phone', 'portable', 'cell'],
            'hotspot': ['mobile', 'phone', 'portable', 'travel', 'wireless', 'tether'],

            # Tech / Gaming
            'gaming': ['xbox', 'playstation', 'nintendo', 'game', 'stream', 'twitch', 'esports'],
            'tech': ['geek', 'nerd', 'computer', 'digital', 'cyber', 'smart', 'iot'],

            # Public / Free
            'public': ['free', 'open', 'city', 'community', 'library', 'park', 'municipal'],
            'free': ['public', 'open', 'guest', 'wifi', 'internet', 'access', 'complimentary'],
        }

    def _lookup_vendor(self, bssid: str) -> str | None:
        """Resolve vendor from BSSID OUI."""
        if not bssid or len(bssid) < 8:
            return None
        if bssid.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return None
        # Clean BSSID and take first 6 chars (OUI)
        clean = bssid.replace(':', '').replace('-', '').upper()
        if len(clean) < 6:
            return None
        oui = clean[:6]
        return self.OUI_DB.get(oui)

    def generate_plan(self, ssid: str, bssid: str, priority_score: int) -> list[AttackRound]:
        """Generate a tailored list of attack rounds."""
        plan = []
        ssid_lower = ssid.lower() if ssid else ""

        # 1. Quick Hybrid (Semantic)
        # Always try semantic variations first if SSID has meaningful words
        semantic_list = self._extract_semantics(ssid)
        if semantic_list:
             plan.append(AttackRound(
                 name='semantic_quick',
                 strategy='custom_words',
                 timeout_sec=120,
                 description=f"Semantic Attack ({len(semantic_list)} vectors)",
                 config={'words': semantic_list}
             ))
        else:
             plan.append(AttackRound(
                 name='quick',
                 strategy='quick',
                 timeout_sec=60,
                 description="Common WiFi passwords"
             ))

        # 2. Vendor Specific
        vendor = self._infer_vendor(bssid, ssid)
        if vendor and vendor in self.vendor_patterns:
            pat = self.vendor_patterns[vendor]
            plan.append(AttackRound(
                name=f"vendor_{vendor.lower()}",
                strategy='mask',
                timeout_sec=300,
                description=pat['desc'],
                config={'mask': pat['mask']}
            ))

        # 3. Date / Year Hybrid
        # Check if SSID contains year patterns or if we should just try years
        current_year = 2026 # Context aware
        if re.search(r'20[0-2][0-9]', ssid_lower):
            # Strong signal for year-based password
            years = [str(y) for y in range(2010, current_year + 2)]
            plan.append(AttackRound(
                name='year_hybrid',
                strategy='year_hybrid',
                timeout_sec=300,
                description="Year-based patterns (SSID + Years)",
                config={'years': years}
            ))

        # 4. Digits (Universal fallback for residential)
        plan.append(AttackRound(
            name='digits',
            strategy='digits_only',
            timeout_sec=300,
            description="Numeric-only (Universal)"
        ))

        # 5. Hybrid / Rules (Standard)
        plan.append(AttackRound(
            name='standard',
            strategy='standard',
            timeout_sec=3600,
            description="Full dictionary + rules"
        ))

        # 6. Ape Mode (if high priority)
        if priority_score > 70:
            plan.append(AttackRound(
                name='ape',
                strategy='ape_mode',
                timeout_sec=14400,
                description="🦍 APE MODE: Massive hybrid attack",
                min_priority=70
            ))

        return plan

    def _extract_semantics(self, ssid: str | None) -> list[str]:
        if not ssid:
            return []

        # 1. Expand CamelCase
        s_expanded = re.sub(r'([a-z])([A-Z])', r'\1 \2', ssid)

        # 2. Split by non-alphanumeric
        tokens = re.split(r'[^a-zA-Z0-9]', s_expanded)
        base_words = [t.lower() for t in tokens if len(t) > 2]

        vectors = set(base_words)
        # Add full SSID lower
        vectors.add(ssid.lower())

        # Expansion
        for w in base_words:
            if w in self.semantic_map:
                vectors.update(self.semantic_map[w])

        # Basic patterns
        expanded = list(vectors)
        return expanded

    def _infer_vendor(self, bssid: str, ssid: str | None) -> str | None:
        def vendor_from_ssid(ssid_value: str | None) -> str | None:
            if not ssid_value:
                return None
            s = ssid_value.lower()
            if 'netgear' in s:
                return 'Netgear'
            if 'tp-link' in s or 'tplink' in s:
                return 'TP-Link'
            if 'linksys' in s:
                return 'Linksys'
            if 'asus' in s:
                return 'Asus'
            if 'xfinity' in s:
                return 'Xfinity'
            if 'google' in s or 'fiber' in s:
                return 'Google'
            return None

        # 1. Direct OUI Lookup (High Confidence)
        vendor = self._lookup_vendor(bssid)
        ssid_vendor = vendor_from_ssid(ssid)
        if vendor:
            vendor_lower = vendor.lower()
            for known in self.vendor_patterns.keys():
                if known.lower() in vendor_lower:
                    return known
            return ssid_vendor or vendor

        # 2. SSID Heuristics (Fallback)
        return ssid_vendor
