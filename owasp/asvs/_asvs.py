import csv
import re
from types import SimpleNamespace
from typing import Self, Union

ASVS_HEADERS = [
    "chapter_id",
    "chapter_name",
    "section_id",
    "section_name",
    "req_id",
    "req_description",
    "level1",
    "level2",
    "level3",
    "cwe",
    "nist",
]

class Chapter:
    def __init__(self, id: int, name: str) -> None:
        self.id = id
        self.uid = f"V{id}"
        self.name = name

    @classmethod
    def from_csv_row(self, csv_row: dict) -> Self:
        uid: str = csv_row[ASVS_HEADERS[0]]
        numeric_id = int(uid.replace("V", ""))
        name = csv_row[ASVS_HEADERS[1]]

        return self(numeric_id, name)

    def __repr__(self) -> str:
        return f"<ASVS Charapter {self.uid}>"

    def __str__(self) -> str:
        return f"OWASP ASVS {self.uid}: {self.name}"


class Section:
    def __init__(self, charapter: Chapter, id: int, name: str) -> None:
        self.id = id
        self.name = name
        self._charapter = charapter
        self._uid = None

    @property
    def charapter(self):
        return self._charapter

    @charapter.setter
    def charapter(self, value: Chapter):
        self._charapter = value
        self._uid = self.charapter.uid + "." + str(self.id)

    @property
    def uid(self):
        return self._uid if self._uid else "Section charapter has not been set"

    @classmethod
    def from_csv_row(self, csv_row: dict) -> Self:
        uid: str = csv_row[ASVS_HEADERS[2]]
        numeric_id = int(uid.partition(".")[2])
        name = csv_row[ASVS_HEADERS[1]]

        return self(charapter=None, id=numeric_id, name=name)

    def __repr__(self) -> str:
        return f"<ASVS Charapter {self.uid}>"

    def __str__(self) -> str:
        return f"OWASP ASVS {self.uid}: {self.name}"


class Requirement:
    def __init__(
        self,
        section: Section,
        id: int,
        description: str,
        link: Union[str | None],
        levels: tuple[bool, bool, bool],
    ) -> None:
        self.id = id
        self.description = description
        self.link = link
        self.level = levels

    def _set_section(self, value: Section):
        self.section = value

    @property
    def section(self):
        return self.section

    @section.setter
    def section(self, value: Section):
        self._section = value
        self._uid = self._section.uid + "." + str(self.id)

    @property
    def uid(self):
        return self._uid if self._uid else "Section charapter has not been set"

    @classmethod
    def from_csv_row(self, csv_row: dict) -> Self:
        uid: str = csv_row[ASVS_HEADERS[4]]
        numeric_id = int(uid.rpartition(".")[2])
        description_dirty = csv_row[ASVS_HEADERS[5]]

        description_clean = description_dirty.split(" ([")[0].strip()

        link_regex = r" \(\[.*]\((.*)\)\)"

        link = None
        if regex_match := re.search(link_regex, description_dirty):
            link = regex_match.group(1)

        # Good luck with this :)
        levels = tuple(
            filter(
                lambda x: x == "✓",
                [csv_row[level_header] for level_header in ASVS_HEADERS[6:9]],
            )
        )

        return self(
            section=None,
            id=numeric_id,
            description=description_clean,
            link=link,
            levels=levels,
        )


def extract_data_from_asvs_csv(
    csv_file_path,
) -> tuple[list[Chapter], list[Section], list[Requirement]]:
    with open(csv_file_path) as fp:
        asvs_csv = csv.DictReader(fp)

        covered = SimpleNamespace(
            chapters=list(),
            sections=list(),
        )

        output = SimpleNamespace(
            chapters=list(),
            sections=list(),
            requirements=list(),
        )

        for requirement in asvs_csv:
            asvs_row = SimpleNamespace(**requirement)

            if asvs_row.chapter_id not in covered.chapters:
                # I have to return it somewhere
                row_charapter = Chapter.from_csv_row(requirement)
                output.chapters.append(row_charapter)
                covered.chapters.append(asvs_row.chapter_id)

            if asvs_row.section_id not in covered.sections:
                row_section = Section.from_csv_row(requirement)
                output.sections.append(row_section)
                covered.sections.append(asvs_row.section_id)

            row_requirement = Requirement.from_csv_row(requirement)
            row_requirement._set_section(row_section)

            output.requirements.append(row_requirement)

    return output.chapters, output.sections, output.requirements
