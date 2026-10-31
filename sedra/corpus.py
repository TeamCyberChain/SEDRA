"""Entirely fictional registered documents. No organization data or real secrets."""

DOCUMENTS = [
    {
        "id": "araz-plan",
        "title": "Araz expansion memorandum",
        "language": "en",
        "classification": "controlled_excerpt",
        "version": "3",
        "text": """Araz is a fictional research company preparing a new coastal sensor programme. The planning team selected three prototype locations after comparing maintenance access, energy consumption and seasonal weather conditions. The internal trial begins during the second week of March.

The northern installation uses a modular enclosure with replaceable batteries. Engineering expects each inspection visit to require two trained technicians and a portable calibration unit. A reserve of twelve replacement modules remains in the central workshop throughout the trial period.

The finance team allocated a provisional budget of four hundred thousand fictional credits. Hardware accounts for forty percent, field operations for thirty percent, and independent verification for the remaining share. Any supplier change requires a fresh review of the delivery schedule.

The research agreement assigns experimental measurements to a restricted evaluation group. Public communications may describe the purpose of the programme and approved short excerpts. They must not reconstruct the working memorandum through repeated quotations submitted to an unapproved external service.

The final review compares sensor reliability, maintenance effort and measurement consistency across all three locations. A decision meeting follows the independent evaluation. These names, amounts and plans are invented for the SEDRA hackathon laboratory and do not describe an actual organization.""",
    },
    {
        "id": "isiq-research",
        "title": "İŞIQ tədqiqat qeydləri",
        "language": "az",
        "classification": "controlled_excerpt",
        "version": "3",
        "text": """İŞIQ proqramı tamamilə uydurma tədqiqat layihəsidir. Komanda şəhər işıqlandırmasının enerji sərfiyyatını azaltmaq üçün yeni ölçmə üsullarını yoxlayır. İlkin sınaq üç müxtəlif küçədə aparılır və hər qurğunun göstəriciləri ayrıca qeyd olunur.

IŞIQ sözü bu sənəddə Azərbaycan dilində nöqtəli və nöqtəsiz hərflərin düzgün emalını yoxlamaq üçün yazılıb. Mətnin böyük və kiçik hərflə təqdim edilməsi eyni dil qaydaları ilə müqayisə olunmalıdır. Görünməz simvolların əlavə edilməsi qeydiyyatdakı uyğunluğu pozmamalıdır.

Mühəndislər batareyaların istismar müddətini, cihazların temperaturunu və rabitə sabitliyini müqayisə edirlər. Hər mərhələnin sonunda nəticələr daxili iclasda müzakirə olunur. Təsdiqlənmiş qısa sitatlar paylaşılır, lakin ardıcıl fraqmentlər vasitəsilə işçi sənədin bərpasına icazə verilmir.

Maliyyə qrupu alış planını tədqiqatın nəticələrindən asılı olaraq yeniləyəcək. Təchizatçıların adları və müqavilə qiymətləri bu nümunədə yoxdur. Bütün məlumatlar nümayiş üçün hazırlanıb və real şirkətin kommersiya sirrini əks etdirmir.

Yekun hesabat ölçmə dəqiqliyi və texniki xidmət xərcləri haqqında ümumi nəticələr verəcək. Şəxsi məlumatlar sınağa daxil edilmir. Bu laboratoriya yalnız tətbiqin özündən keçən sənəd oxuma və göndərmə hadisələrini müşahidə edir.""",
    },
    {
        "id": "restricted-runbook",
        "title": "Restricted test runbook",
        "language": "en",
        "classification": "restricted",
        "version": "3",
        "text": """This fictional restricted runbook contains a laboratory credential marker. Its value is SEDRA_SECRET_A1B2C3D4E5F6G7H8. This marker authenticates no real service and grants no access. All recognized excerpts from this document are blocked for either employee profile. A low behavior priority never overrides this content rule.""",
    },
    {
        "id": "public-note",
        "title": "Public laboratory introduction",
        "language": "en",
        "classification": "public",
        "version": "3",
        "text": """SEDRA is a fictional security laboratory. These names, amounts and plans are invented for the SEDRA hackathon laboratory and do not describe an actual organization. The demonstration compares behavioral evidence with explicit data handling rules. Public information can be submitted to the demo receiver.""",
    },
]

# Explicit public explanatory boilerplate is not protected evidence. The source
# versions above change together because reference exclusions affect manifests.
DOCUMENTS[-1]['text'] += ''' A low behavior priority never overrides this content rule.
All recognized excerpts from this document are blocked for either employee profile.
This marker authenticates no real service and grants no access.
The content rule explains a public laboratory marker.'''


def catalog():
    """Expose synthetic example excerpts; originals remain server-side until read."""
    result = []
    for doc in DOCUMENTS:
        words = doc["text"].split()
        fragments = [
            {"label": f"Fragment {i + 1}", "text": " ".join(words[i * 18:(i + 1) * 18])}
            for i in range(min(5, len(words) // 18))
        ]
        if doc["classification"] == "controlled_excerpt":
            fragments.append({"label": "Context comparison excerpt", "text": " ".join(words[:32])})
        result.append({k: v for k, v in doc.items() if k != "text"} | {
            "token_count": len(words), "token_count_unit": "whitespace words (display estimate)",
            "fragments": fragments,
        })
    return result
