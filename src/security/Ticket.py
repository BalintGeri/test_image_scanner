"""Module for datastructure for Ticket."""


class Ticket:
    """Represents a Ticket."""

    def __init__(self, iid: int, priority: int | None, is_closed: bool, forced_closed: bool):
        """Initialise an instance."""
        self.iid: int = iid
        self.priority: int | None = priority
        self.is_closed: bool = is_closed
        self.forced_closed: bool = forced_closed

    def __str__(self):
        return str("Ticket(" + str(self.iid) + ")")

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash(self.iid)

    def __eq__(self, other: "Ticket"):
        if isinstance(other, Ticket):
            return self.iid == other.iid
        return False


class TicketFactory:
    """Factory for Ticket."""

    iid: int | None = None
    priority: int | None = None
    is_closed: bool | None = None
    forced_closed: bool | None = None

    def build(self):
        """
        Build a ticket instance by factory attributes.

        :return: new Ticket instance
        """
        if self.iid is not None and self.is_closed is not None and self.forced_closed is not None:
            return Ticket(
                iid=self.iid, priority=self.priority, is_closed=self.is_closed, forced_closed=self.forced_closed
            )
        raise LookupError("Factory not satisfied.")
