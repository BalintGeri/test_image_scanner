"""Module for datastructure for Component."""


class Component:
    """Represents a Component."""

    def __init__(
        self,
        name: str,
        full_path: str,
        src: str,
        version: str,
        url_report: str,
        sonar_direct_link: str,
        suggestion: str,
    ):
        """Initialise an instance."""
        self.name: str = name
        self.full_path: str = full_path
        self.src: str = src
        self.version: str = version
        self.url_report: str = url_report
        self.sonar_direct_link: str = sonar_direct_link
        self.suggestion: str = suggestion

    def __str__(self):
        return str("Component(" + str(self.name) + ")")

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other: "Component"):
        if isinstance(other, Component):
            return (self.full_path, self.name, self.src, self.version, self.suggestion) == (
                other.full_path,
                other.name,
                other.src,
                other.version,
                other.suggestion,
            )
        return False


class ComponentFactory:
    """Factory for Component."""

    name: str | None = None
    full_path: str | None = None
    src: str | None = None
    version: str | None = None
    url_report: str | None = None
    sonar_direct_link: str | None = None
    suggestion: str | None = None

    def build(self):
        """
        Build a component instance by factory attributes.

        :return: new Component instance
        """
        if (
            self.name is not None
            and self.full_path is not None
            and self.src is not None
            and self.version is not None
            and self.url_report is not None
            and self.sonar_direct_link is not None
            and self.suggestion is not None
        ):
            return Component(
                name=self.name,
                full_path=self.full_path,
                src=self.src,
                version=self.version,
                url_report=self.url_report,
                sonar_direct_link=self.sonar_direct_link,
                suggestion=self.suggestion,
            )
        raise LookupError("Factory not satisfied.")
